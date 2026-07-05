// Supabase Edge Function: scan-breaches
//
// 매일 자정(pg_cron, 15:00 UTC) 호출되어 회사 계정 유출을 조회하고
// breach_findings / scan_runs 테이블에 마스킹 형태로 적재한다.
//
// 데이터 소스:
//  - HIBP_API_KEY 가 있으면 Have I Been Pwned 도메인 검색(MONITORED_DOMAINS).
//  - 없으면 무료 XposedOrNot 로 MONITORED_EMAILS(개별 계정)를 조회.
//
// 개인정보: 평문 비밀번호·전체 이메일 미저장. 계정은 항상 마스킹(jo***@domain).
//
// 환경변수(Supabase Secrets):
//  - SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY  (Edge 런타임 자동 주입)
//  - MONITORED_EMAILS   쉼표구분 이메일 목록 (무료 XposedOrNot 경로)
//  - MONITORED_DOMAINS  쉼표구분 도메인 목록 (HIBP 경로)
//  - HIBP_API_KEY       (선택) 있으면 도메인 전수 검색

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SERVICE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
const HIBP_API_KEY = Deno.env.get("HIBP_API_KEY")?.trim();
const MONITORED_EMAILS = (Deno.env.get("MONITORED_EMAILS") ?? "")
  .split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);
const MONITORED_DOMAINS = (Deno.env.get("MONITORED_DOMAINS") ?? "")
  .split(",").map((s) => s.trim().toLowerCase()).filter(Boolean);

const HIBP_BASE = "https://haveibeenpwned.com/api/v3";
const XON_BASE = "https://api.xposedornot.com/v1";
const CAVALIER_BASE = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools";
const LEAKCHECK_BASE = "https://leakcheck.io";
const UA = "darkweb-monitor-dashboard-breach-monitor";

// 보조 소스 — 키-게이트(있으면 사용, 없으면 skip). Hudson Rock OSINT 는 무료라 토글로만 제어.
const INTELX_API_KEY = Deno.env.get("INTELX_API_KEY")?.trim();
const INTELX_HOST = Deno.env.get("INTELX_API_HOST")?.trim() || "https://2.intelx.io";
const INTELX_BUCKETS = (Deno.env.get("INTELX_BUCKETS") ?? "").split(",").map((s) => s.trim()).filter(Boolean);
const LEAKCHECK_API_KEY = Deno.env.get("LEAKCHECK_API_KEY")?.trim();
const HUDSONROCK_OSINT = (Deno.env.get("HUDSONROCK_OSINT_ENABLED") ?? "1") !== "0";
const GITHUB_TOKEN = Deno.env.get("GITHUB_TOKEN")?.trim();
const GITHUB_API = "https://api.github.com";

const LEAK_FIELD_KO: Record<string, string> = {
  password: "비밀번호", username: "사용자명", email: "이메일", phone: "전화번호",
  dob: "생년월일", ssn: "주민번호", address: "주소", zip: "우편번호", ip: "IP 주소",
  first_name: "이름", last_name: "이름", name: "이름",
};
function mapLeakFields(fields: string[]): string[] {
  const out = [...new Set((fields ?? []).map((f) => LEAK_FIELD_KO[f]).filter(Boolean))];
  return out.length ? out : ["유출 기록"];
}

const DATA_CLASS_KO: Record<string, string> = {
  "Email addresses": "이메일", Passwords: "비밀번호", Usernames: "사용자명", Names: "이름",
  "Phone numbers": "전화번호", "Physical addresses": "주소", "IP addresses": "IP 주소",
  "Dates of birth": "생년월일", Genders: "성별", "Credit cards": "신용카드",
  "Bank account numbers": "계좌번호", "Security questions and answers": "보안 질문/답변",
  "Auth tokens": "인증 토큰", "Geographic locations": "위치 정보", "Job titles": "직책",
  Employers: "직장", "Social media profiles": "소셜 프로필",
};
const SEVERITY_RANK: Record<string, number> = { low: 0, medium: 1, high: 2, critical: 3 };

function severityFor(dataClasses: string[]): string {
  let sev = "low";
  const bump = (s: string) => { if (SEVERITY_RANK[s] > SEVERITY_RANK[sev]) sev = s; };
  for (const dc of dataClasses) {
    if (["Passwords", "Credit cards", "Bank account numbers"].includes(dc)) bump("critical");
    else if (["Security questions and answers", "Auth tokens"].includes(dc)) bump("high");
    else if (["Phone numbers", "Physical addresses", "Dates of birth", "IP addresses"].includes(dc)) bump("medium");
  }
  return sev;
}
function maskLocal(alias: string) {
  if (!alias) return "***";
  return alias.length <= 2 ? `${alias[0] ?? "*"}***` : `${alias.slice(0, 2)}***`;
}
async function sha1Hex(s: string) {
  const buf = await crypto.subtle.digest("SHA-1", new TextEncoder().encode(s));
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, "0")).join("").slice(0, 12);
}
const isoDate = (iso?: string) => (iso ? String(iso).slice(0, 10) : "");
const koClasses = (l: string[]) => (l ?? []).map((dc) => DATA_CLASS_KO[dc] ?? dc);
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

// fetch 타임아웃 래퍼 — 느린 외부 소스가 전체 스캔을 무한정 묶지 않도록 AbortController 적용(기본 12s).
function fetchT(url: string, opts: RequestInit = {}, ms = 12000): Promise<Response> {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), ms);
  return fetch(url, { ...opts, signal: ctrl.signal }).finally(() => clearTimeout(t));
}

// 관제(SOC) 알림 — 신규 유출/스캔 이상을 능동 통지. 이메일(Resend) 또는 웹훅(Slack/Teams) 지원.
// 본문은 건수·요약·대시보드 링크만(계정/비번 등 PII 미포함). 시크릿 미설정 채널은 조용히 skip.
//  · 이메일: RESEND_API_KEY + NOTIFY_EMAIL(수신주소) 설정 시. 발신은 NOTIFY_EMAIL_FROM(기본 onboarding@resend.dev).
//  · 웹훅:   NOTIFY_WEBHOOK_URL 설정 시.
const NOTIFY_WEBHOOK_URL = Deno.env.get("NOTIFY_WEBHOOK_URL");
const RESEND_API_KEY = Deno.env.get("RESEND_API_KEY");
const NOTIFY_EMAIL = Deno.env.get("NOTIFY_EMAIL"); // 수신 주소(레포에 비공개 — 시크릿)
const NOTIFY_EMAIL_FROM = Deno.env.get("NOTIFY_EMAIL_FROM") || "onboarding@resend.dev";
const DASHBOARD_URL = Deno.env.get("DASHBOARD_URL") || "https://dark.jbax.co.kr";
async function maybeNotify(s: { status: string; newCount: number; total: number; summary: Record<string, number>; infTotal: number; note: string | null }) {
  const isErr = s.status === "error";
  if (!isErr && s.newCount <= 0) return; // 정상 + 신규 없음이면 알릴 내용 없음
  const title = isErr ? "🚨 다크웹 모니터링 · 스캔 이상" : `⚠️ 다크웹 모니터링 · 신규 유출 ${s.newCount}건`;
  const body = isErr
    ? `상태: ${s.status}${s.note ? ` · ${s.note}` : ""}`
    : `신규 ${s.newCount}건 / 총 ${s.total}건 (심각 ${s.summary.critical} · 높음 ${s.summary.high}) · 인포스틸러 ${s.infTotal}건`;
  const text = `${title}\n${body}\n${DASHBOARD_URL}`;
  // 1) 이메일 (Resend)
  if (RESEND_API_KEY && NOTIFY_EMAIL) {
    try {
      await fetchT("https://api.resend.com/emails", {
        method: "POST",
        headers: { "Authorization": `Bearer ${RESEND_API_KEY}`, "Content-Type": "application/json" },
        body: JSON.stringify({ from: NOTIFY_EMAIL_FROM, to: [NOTIFY_EMAIL], subject: title, text }),
      }, 8000);
    } catch (e) { console.warn("[notify] 이메일(Resend) 알림 전송 실패 — 스캔은 계속:", (e as Error).message); }
  }
  // 2) 웹훅 (Slack/Teams/일반)
  if (NOTIFY_WEBHOOK_URL) {
    try {
      await fetchT(NOTIFY_WEBHOOK_URL, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ text }) }, 8000);
    } catch (e) { console.warn("[notify] 웹훅 알림 전송 실패 — 스캔은 계속:", (e as Error).message); }
  }
}

// 견고한 JSON fetch: 429/5xx 는 Retry-After/지수 백오프로 재시도. 실패해도 throw 안 함.
// deno-lint-ignore no-explicit-any
async function fetchJson(url: string, init: { headers?: Record<string, string>; method?: string; body?: string } = {}, opts: { retries?: number; baseDelay?: number } = {}): Promise<{ ok: boolean; status: number; data: any }> {
  const { headers = {}, method = "GET", body } = init;
  const { retries = 2, baseDelay = 800 } = opts;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const res = await fetchT(url, { method, headers: { "user-agent": UA, ...headers }, body });
      if ((res.status === 429 || res.status >= 500) && attempt < retries) {
        const ra = Number(res.headers.get("retry-after"));
        await sleep(ra ? ra * 1000 : baseDelay * (attempt + 1));
        continue;
      }
      // deno-lint-ignore no-explicit-any
      let data: any = null;
      try { data = await res.json(); } catch { /* 비JSON/빈 본문 */ }
      return { ok: res.ok, status: res.status, data };
    } catch (_err) {
      if (attempt < retries) { await sleep(baseDelay * (attempt + 1)); continue; }
      return { ok: false, status: 0, data: null };
    }
  }
  return { ok: false, status: 0, data: null };
}

interface Catalog { [k: string]: { title: string; date: string; dataClasses: string[]; industry?: string; logo?: string; passwordRisk?: string; referenceURL?: string } }

async function loadXonCatalog(): Promise<Catalog> {
  try {
    const res = await fetchT(`${XON_BASE}/breaches`, { headers: { "user-agent": UA } });
    if (!res.ok) return {};
    const body = await res.json();
    const arr = Array.isArray(body) ? body : body.exposedBreaches ?? [];
    const map: Catalog = {};
    for (const b of arr) {
      map[b.breachID] = {
        title: b.breachID, date: isoDate(b.breachedDate),
        dataClasses: Array.isArray(b.exposedData) ? b.exposedData : [],
        industry: b.industry, logo: b.logo, passwordRisk: b.passwordRisk, referenceURL: b.referenceURL,
      };
    }
    return map;
  } catch (e) { console.warn("[xon] 유출 카탈로그 로드 실패 — 제목/분류 메타 비어질 수 있음:", (e as Error).message); return {}; }
}
async function xonCheckEmail(email: string): Promise<string[]> {
  try {
    const res = await fetchT(`${XON_BASE}/check-email/${encodeURIComponent(email)}`, { headers: { "user-agent": UA } });
    if (!res.ok) return [];
    const body = await res.json();
    if (body?.Error) return [];
    const nested = body?.breaches;
    if (Array.isArray(nested) && Array.isArray(nested[0])) return nested[0].filter(Boolean);
    if (Array.isArray(nested)) return nested.filter((x: unknown) => typeof x === "string");
    return [];
  } catch { return []; }
}
async function loadHibpCatalog(): Promise<Catalog> {
  try {
    const res = await fetchT(`${HIBP_BASE}/breaches`, { headers: { "user-agent": UA } });
    if (!res.ok) return {};
    const arr = await res.json();
    const map: Catalog = {};
    for (const b of arr) map[b.Name] = { title: b.Title ?? b.Name, date: isoDate(b.BreachDate), dataClasses: b.DataClasses ?? [] };
    return map;
  } catch (e) { console.warn("[hibp] 유출 카탈로그 로드 실패 — 제목/분류 메타 비어질 수 있음:", (e as Error).message); return {}; }
}
async function hibpDomain(domain: string): Promise<Record<string, string[]> | null> {
  // 도메인 전수 검색 대비: 429 는 Retry-After 만큼 대기 후 재시도.
  for (let attempt = 0; attempt < 4; attempt++) {
    const res = await fetchT(`${HIBP_BASE}/breacheddomain/${encodeURIComponent(domain)}`, {
      headers: { "hibp-api-key": HIBP_API_KEY!, "user-agent": UA },
    });
    if (res.status === 404 || res.status === 204) return null;
    if (res.status === 429) {
      const ra = Number(res.headers.get("retry-after")) || 2 * (attempt + 1);
      await sleep(ra * 1000);
      continue;
    }
    if (!res.ok) throw new Error(`HIBP ${domain} → HTTP ${res.status}`);
    return res.json();
  }
  throw new Error(`HIBP ${domain} → 429 반복(레이트리밋)`);
}

// ── Hudson Rock Cavalier (무료, 키 불필요) — 도메인 전수 인포스틸러 감염 ──────
interface Infostealer {
  domain: string; source: string; total: number; employees: number; users: number;
  third_parties: number; affected_urls: { url: string; type: string; occurrence: number }[];
  scanned_at: string;
}
async function collectCavalier(domains: string[], nowIso: string): Promise<Infostealer[]> {
  const out: Infostealer[] = [];
  for (const domain of domains) {
    try {
      const res = await fetchT(`${CAVALIER_BASE}/search-by-domain?domain=${encodeURIComponent(domain)}`, { headers: { "user-agent": UA } });
      if (!res.ok) continue;
      const d = await res.json();
      const urls = (d?.data?.all_urls ?? []).slice(0, 30).map((u: { url: string; type: string; occurrence: number }) => ({ url: u.url, type: u.type, occurrence: u.occurrence }));
      out.push({
        domain, source: "Hudson Rock Cavalier",
        total: d.total ?? 0, employees: d.employees ?? 0, users: d.users ?? 0,
        third_parties: d.third_parties ?? 0, affected_urls: urls, scanned_at: nowIso,
      });
      await sleep(300);
    } catch (e) { console.warn("[cavalier] 도메인 인포스틸러 조회 실패(건너뜀):", domain, (e as Error).message); }
  }
  return out;
}

type RawFinding = Finding & { is_new: boolean; discovered_at: string };

// ── Hudson Rock 계정별 인포스틸러 (무료) → breach_findings ───────────────────
// 민감값(top_passwords·ip·PC명)은 저장하지 않고 마스킹 계정 + 분류 + 카운트만 남긴다.
interface InfostealerHostRow {
  host_id: string; account_masked: string; domain: string;
  computer_name: string | null; operating_system: string | null; ip: string | null;
  date_compromised: string | null; stealer_family: string | null; malware_path: string | null;
  antiviruses: string[]; total_corporate_services: number; total_user_services: number;
  top_passwords: string[]; top_logins: string[]; scanned_at: string; last_scan_tag?: string;
}

async function collectCavalierAccounts(accounts: string[], nowIso: string): Promise<{ findings: RawFinding[]; hosts: InfostealerHostRow[] }> {
  const findings: RawFinding[] = [];
  const hosts: InfostealerHostRow[] = [];
  for (const acct of accounts) {
    const email = acct.trim().toLowerCase();
    const [alias, domain] = email.split("@");
    if (!alias || !domain) continue;
    const r = await fetchJson(`${CAVALIER_BASE}/search-by-email?email=${encodeURIComponent(email)}`, {}, { retries: 3, baseDelay: 1500 }); // #6 레이트리밋(429) 백오프 강화
    const stealers = Array.isArray(r.data?.stealers) ? r.data.stealers : [];
    if (stealers.length) {
      const accountMasked = `${maskLocal(alias)}@${domain}`;
      const seen = new Set<string>();
      let corp = 0, hasPw = false, hasLogin = false, last = "";
      const families = new Set<string>();
      // deno-lint-ignore no-explicit-any
      for (const s of stealers as any[]) {
        const key = `${s.computer_name}|${s.date_compromised}|${s.ip}`;
        if (seen.has(key)) continue;
        seen.add(key);
        corp += Number(s.total_corporate_services || 0);
        if (Array.isArray(s.top_passwords) && s.top_passwords.length) hasPw = true;
        if (Array.isArray(s.top_logins) && s.top_logins.length) hasLogin = true;
        if (s.stealer_family) families.add(s.stealer_family);
        const d = String(s.date_compromised || "").slice(0, 10);
        if (d > last) last = d;
        // 호스트 상세(피해 PC). top_passwords/ip 는 Hudson Rock 이 부분 마스킹한 값만 저장.
        hosts.push({
          host_id: await sha1Hex(`${accountMasked}|${s.computer_name || ""}|${s.date_compromised || ""}|${s.ip || ""}`),
          account_masked: accountMasked, domain,
          computer_name: s.computer_name || null,
          operating_system: s.operating_system || null,
          ip: s.ip || null,
          date_compromised: d || null,
          stealer_family: s.stealer_family || null,
          malware_path: s.malware_path || null,
          antiviruses: Array.isArray(s.antiviruses) ? s.antiviruses : [],
          total_corporate_services: Number(s.total_corporate_services || 0),
          total_user_services: Number(s.total_user_services || 0),
          top_passwords: Array.isArray(s.top_passwords) ? s.top_passwords.slice(0, 12) : [],
          top_logins: Array.isArray(s.top_logins) ? s.top_logins.slice(0, 12) : [],
          scanned_at: nowIso,
        });
      }
      const dataClasses: string[] = [];
      if (hasLogin) dataClasses.push("자격증명");
      if (hasPw) dataClasses.push("비밀번호");
      dataClasses.push("인포스틸러 감염");
      findings.push(await mkRawFinding({
        domain, alias,
        breachName: families.size ? `Infostealer (${[...families].join(", ")})` : "Infostealer",
        breachTitle: `인포스틸러 감염 (${seen.size}대 기기)`,
        breachDate: last, dataClassesKo: dataClasses,
        severity: corp > 0 ? "high" : "medium",
        source: "Hudson Rock Cavalier (계정별)",
      }, nowIso));
    }
    await sleep(700); // 무료 OSINT 공정사용 ~1.4 req/s (교차매핑으로 호출 늘어 약간 완화)
  }
  return { findings, hosts };
}

// ── Intelligence X (키-게이트) → breach_findings ────────────────────────────
async function collectIntelx(domains: string[], nowIso: string): Promise<{ findings: RawFinding[]; used: boolean; count: number }> {
  if (!INTELX_API_KEY) return { findings: [], used: false, count: 0 };
  const headers = { "x-key": INTELX_API_KEY, "content-type": "application/json" };
  const info = await fetchJson(`${INTELX_HOST}/authenticate/info`, { headers });
  if (!info.ok) return { findings: [], used: false, count: 0 };
  const findings: RawFinding[] = [];
  for (const domain of domains) {
    const start = await fetchJson(`${INTELX_HOST}/intelligent/search`, {
      method: "POST", headers,
      body: JSON.stringify({ term: domain, maxresults: 100, media: 0, sort: 4, timeout: 5, ...(INTELX_BUCKETS.length ? { buckets: INTELX_BUCKETS } : {}) }),
    });
    const id = start.data?.id;
    if (!id || start.data?.status === 2) continue;
    // deno-lint-ignore no-explicit-any
    const records: any[] = [];
    for (let i = 0; i < 8; i++) {
      const r = await fetchJson(`${INTELX_HOST}/intelligent/search/result?id=${encodeURIComponent(id)}&limit=100`, { headers });
      if (Array.isArray(r.data?.records)) records.push(...r.data.records);
      const st = r.data?.status;
      if (st === 1 || st === 2) break;
      await sleep(1200);
    }
    const seen = new Set<string>();
    for (const rec of records) {
      if (seen.has(rec.systemid)) continue;
      seen.add(rec.systemid);
      const bucket = String(rec.bucket || "");
      const name = String(rec.name || bucket || "IntelX record");
      const severity = /private|credential|combo|dump/i.test(`${bucket} ${name}`) ? "high" : /leak|public/i.test(bucket) ? "medium" : "low";
      const dataClasses = /combo|dump|cred/i.test(name) ? ["이메일", "비밀번호"] : /paste/i.test(bucket) ? ["페이스트"] : ["유출 기록"];
      findings.push(await mkRawFinding({ domain, alias: "*", breachName: name.slice(0, 80), breachTitle: name.slice(0, 120), breachDate: String(rec.date || "").slice(0, 10), dataClassesKo: dataClasses, severity, source: "Intelligence X" }, nowIso, rec.systemid));
    }
  }
  return { findings, used: true, count: findings.length };
}

// ── LeakCheck → breach_findings ─────────────────────────────────────────────
// 키 있으면 v2 type=domain(평문 password 는 절대 저장 안 함), 없으면 무료 public 계정별.
async function collectLeakcheck(domains: string[], accounts: string[], nowIso: string): Promise<{ findings: RawFinding[]; used: boolean; count: number; mode: string }> {
  if (LEAKCHECK_API_KEY) {
    const findings: RawFinding[] = [];
    for (const domain of domains) {
      let offset = 0;
      for (let page = 0; page < 10; page++) {
        const r = await fetchJson(`${LEAKCHECK_BASE}/api/v2/query/${encodeURIComponent(domain)}?type=domain&limit=100&offset=${offset}`, { headers: { "X-API-Key": LEAKCHECK_API_KEY } });
        if (!r.ok) break;
        const result = Array.isArray(r.data?.result) ? r.data.result : [];
        for (const e of result) {
          const email = String(e.email || "").toLowerCase();
          const [alias, dm] = email.includes("@") ? email.split("@") : ["*", domain];
          const fields = Array.isArray(e.fields) ? e.fields : [];
          const sev = fields.includes("password") || fields.includes("ssn") ? "high" : fields.includes("dob") || fields.includes("address") ? "medium" : "low";
          // password 등 평문은 매핑에서 제외 — fields(분류)만 사용.
          findings.push(await mkRawFinding({ domain: dm || domain, alias: alias || "*", breachName: e.source?.name || "LeakCheck", breachTitle: e.source?.name || "LeakCheck", breachDate: String(e.source?.breach_date || "").slice(0, 10), dataClassesKo: mapLeakFields(fields), severity: sev, source: "LeakCheck" }, nowIso, email || undefined));
        }
        if (result.length < 100) break;
        offset += 100;
        await sleep(400);
      }
    }
    return { findings, used: true, count: findings.length, mode: "v2-domain" };
  }
  if (accounts.length) {
    const findings: RawFinding[] = [];
    for (const acct of accounts) {
      const email = acct.trim().toLowerCase();
      const [alias, domain] = email.split("@");
      if (!alias || !domain) continue;
      const r = await fetchJson(`${LEAKCHECK_BASE}/api/public?check=${encodeURIComponent(email)}`);
      const sources = Array.isArray(r.data?.sources) ? r.data.sources : [];
      const fields = Array.isArray(r.data?.fields) ? r.data.fields : [];
      const dataClasses = mapLeakFields(fields);
      const sev = fields.includes("password") || fields.includes("ssn") ? "high" : "low";
      for (const src of sources) {
        findings.push(await mkRawFinding({ domain, alias, breachName: src.name || "LeakCheck", breachTitle: src.name || "LeakCheck", breachDate: String(src.date || ""), dataClassesKo: dataClasses, severity: sev, source: "LeakCheck (public)" }, nowIso, src.name));
      }
      await sleep(1100);
    }
    return { findings, used: true, count: findings.length, mode: "public" };
  }
  return { findings: [], used: false, count: 0, mode: "" };
}

// ── GitHub 공개 노출 검색 (키-게이트, 무료 합법) → breach_findings ───────────
async function collectGithub(domains: string[], nowIso: string): Promise<{ findings: RawFinding[]; used: boolean; count: number }> {
  if (!GITHUB_TOKEN) return { findings: [], used: false, count: 0 };
  const headers = {
    Authorization: `Bearer ${GITHUB_TOKEN}`,
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
  };
  const findings: RawFinding[] = [];
  const seen = new Set<string>();
  for (const domain of domains) {
    const q = encodeURIComponent(`"@${domain}" password`); // 이메일형(@도메인)으로 노이즈 축소
    const r = await fetchJson(`${GITHUB_API}/search/code?q=${q}&per_page=20`, { headers }, { retries: 1, baseDelay: 2000 });
    // deno-lint-ignore no-explicit-any
    const items: any[] = Array.isArray(r.data?.items) ? r.data.items : [];
    for (const it of items) {
      const repo = it.repository?.full_name || "";
      const path = it.path || "";
      const url = it.html_url || "";
      const key = `${repo}/${path}`;
      if (!repo || seen.has(key)) continue;
      seen.add(key);
      findings.push(await mkRawFinding({
        domain, alias: "*",
        breachName: "GitHub 공개 노출",
        breachTitle: `${repo} · ${path}`.slice(0, 120),
        dataClassesKo: ["공개 코드 노출", "자격증명 의심"],
        severity: "high",
        source: "공개 노출 (GitHub)",
        referenceUrl: url,
      }, nowIso, key));
    }
    await sleep(1500); // 코드 검색 레이트리밋 배려(Edge 실행시간 한계 고려해 짧게)
  }
  return { findings, used: true, count: findings.length };
}

// ── 공개 소스코드 수동 큐레이션 노출 → breach_findings ──────────────────────
// 정본(single source of truth): 레포의 data/security/source_code_exposures.json.
// Edge 는 단일파일 배포라 아래 CURATED_EXPOSURES 로 미러링한다(JSON 수정 시 함께 갱신 — 소량·저빈도).
// 매 스캔 이 노출들을 breach_findings 로 재적재해 대시보드 조치추적(008)·알림·stale 관리에 포함.
// info(정보성)·reviewed(조치불요) 는 제외하고 실제 조치 대상만 적재. 민감값 미저장(레포/URL 포인터만).
const SC_DATACLASS: Record<string, string[]> = {
  email: ["임직원 이메일", "공개 코드 노출"],
  content: ["웹콘텐츠 스크랩"],
  config: ["내부 시스템 URL"],
  domain: ["만료 도메인"],
  vuln: ["웹취약점(XSS)"],
  info: ["참고"],
};
const SC_BREACHNAME: Record<string, string> = {
  email: "공개 소스코드 이메일 노출",
  content: "공개 소스코드 콘텐츠 스크랩",
  config: "공개 소스코드 내부 URL 노출",
  domain: "만료 도메인 노출",
  vuln: "웹취약점 (OpenBugBounty)",
  info: "공개 소스코드 참고",
};
interface CuratedExposure { id: string; type: string; severity: string; domain: string; subject: string; repo: string; url: string; status?: string }
const CURATED_EXPOSURES: CuratedExposure[] = [
  { id: "gh-hantj-kjbank", type: "email", severity: "medium", domain: "kjbank.com", subject: "hantj@kjbank.com", repo: "HanTJ/hwp-report-generator", url: "https://github.com/HanTJ/hwp-report-generator" },
  { id: "gh-kjb736-kjbank", type: "email", severity: "medium", domain: "kjbank.com", subject: "KJB736@kjbank.com", repo: "nexteco/starbucks", url: "https://github.com/nexteco/starbucks" },
  { id: "gh-sej-wooricap", type: "email", severity: "high", domain: "wooricap.com", subject: "sej@wooricap.com (+전화·이름)", repo: "DongwooChae/QuantifyPro", url: "https://github.com/DongwooChae/QuantifyPro" },
  { id: "gh-ljj282-wooricap", type: "email", severity: "medium", domain: "wooricap.com", subject: "ljj282@wooricap.com", repo: "gohdong/image_test", url: "https://github.com/gohdong/image_test" },
  { id: "gh-jbfin-scrape", type: "content", severity: "low", domain: "jbfg.com", subject: "JB 웹콘텐츠 대량 스크랩", repo: "Minhyuckleee/JB_fin", url: "https://github.com/Minhyuckleee/JB_fin" },
  { id: "gh-compliance-sentinel", type: "challenge", severity: "info", domain: "jbfg.com", subject: "Fin:AI Challenge 참가작", repo: "yosyus-Yo/JB_Project-Compliance-Sentinel", url: "https://github.com/yosyus-Yo/JB_Project-Compliance-Sentinel", status: "reviewed" },
  { id: "gh-expired-jbwooricap", type: "domain", severity: "low", domain: "wooricap.com", subject: "jb-wooricap.com (만료 도메인)", repo: "cirosantilli/expired-domain-names-by-day-2021", url: "https://github.com/cirosantilli/expired-domain-names-by-day-2021" },
  { id: "gh-internal-urls", type: "config", severity: "low", domain: "kjbank.com", subject: "내부/뱅킹 시스템 URL 하드코딩(다수 레포)", repo: "여러 레포(scordi-front/StepGuide/TableClothCatalog 등)", url: "https://github.com/search?q=pib.kjbank.com+OR+emp.wooricap.com&type=code" },
  { id: "obb-kjbank-xss", type: "vuln", severity: "high", domain: "kjbank.com", subject: "kjbank.co.kr XSS (OpenBugBounty)", repo: "OpenBugBounty OBB:256489", url: "https://www.openbugbounty.org/reports/256489/" },
  { id: "gh-jbfg-org", type: "info", severity: "info", domain: "jbfg.com", subject: "github.com/JBFG (공개 조직)", repo: "JBFG", url: "https://github.com/JBFG" },
];
async function collectCuratedExposures(nowIso: string): Promise<{ findings: RawFinding[]; used: boolean; count: number }> {
  const findings: RawFinding[] = [];
  for (const e of CURATED_EXPOSURES) {
    if (e.status === "reviewed" || e.severity === "info") continue; // 정보성·조치완료 제외
    const alias = e.type === "email" ? String(e.subject || "").split("@")[0].trim() : "*";
    const sev = ["low", "medium", "high", "critical"].includes(e.severity) ? e.severity : "medium";
    findings.push(await mkRawFinding({
      domain: e.domain || "jbfg.com",
      alias: alias || "*",
      breachName: SC_BREACHNAME[e.type] || "공개 소스코드 노출",
      // email 타입은 subject 가 전체 이메일 → 제목엔 레포만(전체 이메일 미저장 불변식). 전체값은 RLS account 로.
      breachTitle: (e.type === "email" ? (e.repo || "공개 소스코드") : `${e.subject || ""}${e.repo ? ` · ${e.repo}` : ""}`).slice(0, 120),
      dataClassesKo: SC_DATACLASS[e.type] || ["공개 코드 노출"],
      severity: sev,
      source: "공개 소스코드 점검 (수동 큐레이션)",
      referenceUrl: e.url || "",
    }, nowIso, `sc|${e.id}`));
  }
  return { findings, used: true, count: findings.length };
}

// ── ProxyNova COMB 콤보리스트 검색 (무료 키리스, 합법 공개) → breach_findings ──
// 다크웹 유통 콤보리스트(33억 email:password 컴파일)에서 도메인 단위로 노출 계정을 열거.
// 명부(MONITORED_EMAILS) 없이도 우리 도메인 노출 계정을 찾는다. 평문 비번은 절대 저장 안 함(분류만).
// 주의: API 가 substring/토큰 퍼지매칭이라 반드시 email 이 정확히 @domain 으로 끝나는지 가드(없으면 무관 잡음 유입).
// 날짜 정규화: "2019-01"/"2019" 도 유효 날짜(YYYY-MM-DD)로, 아니면 null (insert 오류 방지)
function normBreachDate(d: unknown): string | null {
  const s = String(d ?? "").trim();
  if (/^\d{4}-\d{2}-\d{2}/.test(s)) return s.slice(0, 10);
  if (/^\d{4}-\d{2}$/.test(s)) return `${s}-01`;
  if (/^\d{4}$/.test(s)) return `${s}-01-01`;
  return null;
}

// 정합성 검증: 콤보리스트는 잡음(URL 조각·형식오류 "이메일")이 섞여 @도메인 접미사만으로는 부족.
// 로컬파트 형식을 검증해 www.xxx / URL / 비정상 형식을 걸러낸다(예: www.1004@domain 차단).
function plausibleEmail(email: string): boolean {
  const at = email.indexOf("@");
  if (at <= 0 || email.indexOf("@", at + 1) !== -1) return false; // '@' 정확히 1개, 로컬 비어있지 않음
  const local = email.slice(0, at);
  if (local.length > 64) return false;                         // RFC 로컬파트 상한
  if (!/^[a-z0-9._%+\-]+$/.test(local)) return false;          // 허용 문자만(이미 소문자)
  if (/^\.|\.$|\.\./.test(local)) return false;                // 선두/말미/연속 점 금지(RFC)
  if (/^www\d*\./.test(local) || /https?|:\/\//.test(local)) return false; // URL/파싱 아티팩트
  return true;
}

async function collectProxynovaComb(domains: string[], nowIso: string): Promise<{ findings: RawFinding[]; used: boolean; count: number; emails: string[]; hosts: InfostealerHostRow[] }> {
  const findings: RawFinding[] = [];
  const emails = new Set<string>(); // 노출 계정 — LeakCheck 유출이력 보강용
  for (const domain of domains) {
    const suffix = `@${domain.toLowerCase()}`;
    const seen = new Set<string>();
    for (let start = 0; start < 300; start += 100) { // 우리 도메인은 소량이라 1~2페이지면 충분(안전상한 300)
      const r = await fetchJson(`https://api.proxynova.com/comb?query=${encodeURIComponent(suffix)}&start=${start}&limit=100`, {}, { retries: 1, baseDelay: 1000 });
      const lines: string[] = Array.isArray(r.data?.lines) ? r.data.lines : [];
      if (!lines.length) break;
      for (const line of lines) {
        const i = line.indexOf(":"); // 비번에 ':' 가능 → 첫 ':' 기준 분리. 우측(평문 비번)은 폐기.
        const email = (i === -1 ? line : line.slice(0, i)).trim().toLowerCase();
        if (!email.endsWith(suffix)) continue; // 정확매칭 가드(퍼지매치 잡음 차단)
        if (!plausibleEmail(email)) continue;  // 정합성 가드(URL 조각·형식오류 제거)
        const alias = email.slice(0, email.length - suffix.length);
        if (!alias || seen.has(email)) continue;
        seen.add(email);
        emails.add(email);
        findings.push(await mkRawFinding({
          domain, alias,
          breachName: "COMB 통합본 (다크웹 유통)",
          breachTitle: "COMB — 2021년 약 32억건 email:password 유출 통합본(다크웹·해킹포럼 유통)",
          breachDate: "2021-02-01", // COMB 통합본이 등장한 시점(2021-02). 개별 계정 유출시점이 아니라 통합본 공개 시점.
          dataClassesKo: ["이메일", "비밀번호"],
          severity: "high",
          source: "콤보리스트 (ProxyNova COMB)",
        }, nowIso, "comb"));
      }
      if (lines.length < 100) break;
      await sleep(400);
    }
    await sleep(500);
  }
  // 보강을 병렬로(#4): 유출이력(LeakCheck+XON) ∥ 인포스틸러 교차(Hudson Rock) — 서로 다른 서비스라
  // 동시에 돌려 지연을 절반 가까이 단축(각 서비스는 자기 레이트 안에서 페이싱). 평문 미수집(소스명·날짜·분류만).
  const emailArr = [...emails];
  const enrichBreachHistory = async (): Promise<RawFinding[]> => {
    const out: RawFinding[] = [];
    const xonCatalog = await loadXonCatalog();
    for (const email of emailArr) {
      const at = email.indexOf("@");
      const alias = email.slice(0, at), dm = email.slice(at + 1);
      // LeakCheck + XposedOrNot 동시(서로 다른 서비스)
      const [lc, xnames] = await Promise.all([
        fetchJson(`${LEAKCHECK_BASE}/api/public?check=${encodeURIComponent(email)}`, {}, { retries: 1, baseDelay: 800 }),
        xonCheckEmail(email),
      ]);
      // deno-lint-ignore no-explicit-any
      const sources: any[] = Array.isArray(lc.data?.sources) ? lc.data.sources : [];
      const fields: string[] = Array.isArray(lc.data?.fields) ? lc.data.fields : [];
      for (const s of sources) {
        const name = String(s?.name ?? "").trim() || "미상 유출 출처";
        out.push(await mkRawFinding({ domain: dm, alias, breachName: name, breachTitle: `${name} 유출 이력`, breachDate: normBreachDate(s?.date) ?? undefined, dataClassesKo: mapLeakFields(fields), severity: fields.includes("password") ? "high" : "medium", source: "유출이력 (LeakCheck)" }, nowIso, `lc|${name}`));
      }
      for (const name of xnames) {
        const meta = xonCatalog[name];
        const dc = meta?.dataClasses ?? [];
        out.push(await mkRawFinding({ domain: dm, alias, breachName: name, breachTitle: meta?.title ? `${meta.title} 유출 이력` : `${name} 유출 이력`, breachDate: normBreachDate(meta?.date) ?? undefined, dataClassesKo: dc.length ? koClasses(dc) : ["유출 기록"], severity: dc.length ? severityFor(dc) : "medium", source: "유출이력 (XposedOrNot)" }, nowIso, `xon|${name}`));
      }
      await sleep(300); // LeakCheck 레이트(~100/min) 내 페이싱
    }
    return out;
  };
  const [enrichFindings, cav] = await Promise.all([
    enrichBreachHistory(),
    HUDSONROCK_OSINT ? collectCavalierAccounts(emailArr, nowIso) : Promise.resolve({ findings: [] as RawFinding[], hosts: [] as InfostealerHostRow[] }),
  ]);
  findings.push(...enrichFindings, ...cav.findings);
  return { findings, used: true, count: findings.length, emails: emailArr, hosts: cav.hosts };
}

interface Finding {
  finding_id: string; account_masked: string; account: string; domain: string; breach_name: string;
  breach_title: string; breach_date: string | null; data_classes: string[]; severity: string;
  password_risk?: string; industry?: string; reference_url?: string; breach_logo?: string; source?: string;
}
async function mkFinding(domain: string, alias: string, name: string, meta: Catalog[string], nowIso: string): Promise<Finding & { is_new: boolean; discovered_at: string }> {
  return {
    finding_id: await sha1Hex(`${domain}|${alias}|${name}`),
    account_masked: `${maskLocal(alias)}@${domain}`,
    account: `${alias}@${domain}`, // 식별(full) — RLS(authenticated)로만 노출
    domain, breach_name: name, breach_title: meta?.title || name,
    breach_date: meta?.date || null, data_classes: koClasses(meta?.dataClasses ?? []),
    severity: severityFor(meta?.dataClasses ?? []),
    password_risk: meta?.passwordRisk, industry: meta?.industry,
    reference_url: meta?.referenceURL, breach_logo: meta?.logo,
    is_new: false, discovered_at: nowIso,
  };
}

// 카탈로그 없이 보조 소스가 직접 finding 을 만들 때 사용. dataClasses 는 이미 한글 분류.
// idSeed 로 finding_id 충돌 방지(소스별 레코드). alias="*" = 도메인 단위(특정 계정 없음).
async function mkRawFinding(
  o: { domain: string; alias: string; breachName: string; breachTitle?: string; breachDate?: string; dataClassesKo: string[]; severity: string; source: string; referenceUrl?: string },
  nowIso: string, idSeed = "",
): Promise<Finding & { is_new: boolean; discovered_at: string }> {
  const aliasKey = o.alias || "*";
  return {
    finding_id: await sha1Hex(`${o.domain}|${aliasKey}|${idSeed ? `${o.breachName}|${idSeed}` : o.breachName}`),
    account_masked: aliasKey === "*" ? `*@${o.domain}` : `${maskLocal(aliasKey)}@${o.domain}`,
    account: aliasKey === "*" ? "" : `${aliasKey}@${o.domain}`,
    domain: o.domain, breach_name: o.breachName, breach_title: o.breachTitle || o.breachName,
    breach_date: o.breachDate || null, data_classes: o.dataClassesKo, severity: o.severity,
    reference_url: o.referenceUrl, source: o.source, is_new: false, discovered_at: nowIso,
  };
}

// ── Supabase REST helpers ──────────────────────────────────────────────────
const sbHeaders = { apikey: SERVICE_KEY, Authorization: `Bearer ${SERVICE_KEY}`, "Content-Type": "application/json" };
async function sbGetExistingIds(): Promise<Set<string>> {
  const res = await fetchT(`${SUPABASE_URL}/rest/v1/breach_findings?select=finding_id`, { headers: sbHeaders });
  if (!res.ok) return new Set();
  const rows = await res.json();
  return new Set(rows.map((r: { finding_id: string }) => r.finding_id));
}
async function sbUpsert(rows: unknown[]) {
  if (!rows.length) return;
  const res = await fetchT(`${SUPABASE_URL}/rest/v1/breach_findings?on_conflict=finding_id`, {
    method: "POST",
    headers: { ...sbHeaders, Prefer: "resolution=merge-duplicates,return=minimal" },
    body: JSON.stringify(rows),
  });
  if (!res.ok) throw new Error(`upsert HTTP ${res.status} ${(await res.text()).slice(0, 200)}`);
}
async function sbDeleteStale(scanTag: string) {
  // 이번 스캔에서 안 본 항목(다른 tag 또는 null) 제거 = 현재 노출만 유지.
  const res = await fetchT(`${SUPABASE_URL}/rest/v1/breach_findings?or=(last_scan_tag.neq.${scanTag},last_scan_tag.is.null)`, {
    method: "DELETE", headers: { ...sbHeaders, Prefer: "return=minimal" },
  });
  if (!res.ok) console.warn(`stale delete HTTP ${res.status}`);
}
async function sbInsertScanRun(run: unknown) {
  const res = await fetchT(`${SUPABASE_URL}/rest/v1/scan_runs`, {
    method: "POST", headers: { ...sbHeaders, Prefer: "return=minimal" }, body: JSON.stringify(run),
  });
  if (!res.ok) console.warn(`scan_run insert HTTP ${res.status}`);
}
async function sbUpsertInfostealer(rows: Infostealer[]) {
  if (!rows.length) return;
  const res = await fetchT(`${SUPABASE_URL}/rest/v1/infostealer_findings?on_conflict=domain`, {
    method: "POST",
    headers: { ...sbHeaders, Prefer: "resolution=merge-duplicates,return=minimal" },
    body: JSON.stringify(rows),
  });
  if (!res.ok) console.warn(`infostealer upsert HTTP ${res.status} ${(await res.text()).slice(0, 200)}`);
}
async function sbUpsertInfostealerHosts(rows: InfostealerHostRow[]) {
  if (!rows.length) return;
  const res = await fetchT(`${SUPABASE_URL}/rest/v1/infostealer_hosts?on_conflict=host_id`, {
    method: "POST",
    headers: { ...sbHeaders, Prefer: "resolution=merge-duplicates,return=minimal" },
    body: JSON.stringify(rows),
  });
  if (!res.ok) console.warn(`infostealer_hosts upsert HTTP ${res.status} ${(await res.text()).slice(0, 200)}`);
}
async function sbDeleteStaleHosts(scanTag: string) {
  // 이번 스캔에서 안 본 호스트 제거 = 현재 모니터링 계정의 감염만 유지.
  const res = await fetchT(`${SUPABASE_URL}/rest/v1/infostealer_hosts?or=(last_scan_tag.neq.${scanTag},last_scan_tag.is.null)`, {
    method: "DELETE", headers: { ...sbHeaders, Prefer: "return=minimal" },
  });
  if (!res.ok) console.warn(`infostealer_hosts stale delete HTTP ${res.status}`);
}

Deno.serve(async (req) => {
  // 인증: verify_jwt=false 로 두고 공유 시크릿(SCAN_SECRET) 헤더로 보호.
  // (pg_cron 이 x-scan-secret 헤더로 호출. SCAN_SECRET 미설정 시 검사 생략.)
  const expected = Deno.env.get("SCAN_SECRET");
  if (expected && req.headers.get("x-scan-secret") !== expected) {
    return new Response(JSON.stringify({ ok: false, error: "unauthorized" }), {
      status: 401, headers: { "Content-Type": "application/json" },
    });
  }

  const nowIso = new Date().toISOString();
  // PostgREST 필터(or=...neq.)에 들어가므로 특수문자(. : -) 제거 — 숫자만.
  const scanTag = `scan_${nowIso.replace(/[^0-9]/g, "")}`;
  let findings: RawFinding[] = [];
  let status = "ok";
  let source = "";
  let note: string | null = null;
  let primaryCount = 0;
  const provenanceExtra: { name: string; kind: string; endpoint: string; count: number; scannedAt: string }[] = [];
  let infostealerHosts: InfostealerHostRow[] = [];

  try {
    if (HIBP_API_KEY && MONITORED_DOMAINS.length) {
      source = "Have I Been Pwned (도메인 검색 API)";
      const catalog = await loadHibpCatalog();
      for (const domain of MONITORED_DOMAINS) {
        const aliasMap = await hibpDomain(domain);
        for (const [alias, names] of Object.entries(aliasMap ?? {})) {
          for (const name of names) findings.push(await mkFinding(domain, alias, name, catalog[name], nowIso));
        }
      }
    } else if (MONITORED_EMAILS.length) {
      source = "XposedOrNot (계정별 유출 조회, 무료)";
      const catalog = await loadXonCatalog();
      for (const email of MONITORED_EMAILS) {
        const [alias, domain] = email.split("@");
        if (!alias || !domain) continue;
        const names = await xonCheckEmail(email);
        for (const name of names) findings.push(await mkFinding(domain, alias, name, catalog[name], nowIso));
        await sleep(350);
      }
    } else {
      status = "no_source";
      source = "(모니터링 대상 미설정)";
      note = "MONITORED_EMAILS 또는 (HIBP_API_KEY + MONITORED_DOMAINS) 시크릿을 설정하세요.";
    }
  } catch (err) {
    status = "error";
    note = `조회 실패: ${(err as Error).message}`;
  }

  // 보조 소스 (정상 스캔 한정) — 키 있으면/무료면 추가 수집 후 병합 + is_new 계산
  if (status === "ok") {
    for (const f of findings) f.source = f.source || source; // 1차 소스 라벨
    primaryCount = findings.length;

    try { // 보조 소스 실패가 전체 스캔을 죽이지 않도록 격리
    // IntelX (도메인 전수, 키-게이트)
    if (INTELX_API_KEY && MONITORED_DOMAINS.length) {
      const ix = await collectIntelx(MONITORED_DOMAINS, nowIso);
      if (ix.used) { findings.push(...ix.findings); provenanceExtra.push({ name: "Intelligence X", kind: "breach", endpoint: "2.intelx.io /intelligent/search", count: ix.count, scannedAt: nowIso }); }
    }
    // LeakCheck (키 있으면 도메인 v2, 없으면 무료 public 계정별)
    if (LEAKCHECK_API_KEY ? MONITORED_DOMAINS.length : MONITORED_EMAILS.length) {
      const lc = await collectLeakcheck(MONITORED_DOMAINS, MONITORED_EMAILS, nowIso);
      if (lc.used) { findings.push(...lc.findings); provenanceExtra.push({ name: lc.mode === "v2-domain" ? "LeakCheck" : "LeakCheck (public)", kind: "breach", endpoint: lc.mode === "v2-domain" ? "leakcheck.io /api/v2/query?type=domain" : "leakcheck.io /api/public", count: lc.count, scannedAt: nowIso }); }
    }
    // Hudson Rock 계정별 인포스틸러 (무료) → breach_findings + 호스트 상세
    if (HUDSONROCK_OSINT && MONITORED_EMAILS.length) {
      const hr = await collectCavalierAccounts(MONITORED_EMAILS, nowIso);
      infostealerHosts = hr.hosts;
      if (hr.findings.length) { findings.push(...hr.findings); provenanceExtra.push({ name: "Hudson Rock Cavalier (계정별)", kind: "breach", endpoint: "cavalier.hudsonrock.com /search-by-email", count: hr.findings.length, scannedAt: nowIso }); }
    }
    // GitHub 공개 노출 (키-게이트, 무료 합법 크롤링)
    if (GITHUB_TOKEN && MONITORED_DOMAINS.length) {
      const gh = await collectGithub(MONITORED_DOMAINS, nowIso);
      if (gh.used) { findings.push(...gh.findings); provenanceExtra.push({ name: "공개 노출 (GitHub)", kind: "breach", endpoint: "api.github.com /search/code", count: gh.count, scannedAt: nowIso }); }
    }
    // ProxyNova COMB 콤보리스트 (무료 키리스) — 도메인 단위 노출 계정 열거
    if (MONITORED_DOMAINS.length) {
      const cb = await collectProxynovaComb(MONITORED_DOMAINS, nowIso);
      if (cb.used) {
        // cb.findings 에는 COMB + 유출이력(LeakCheck/XON) + 인포스틸러 교차가 병렬수집되어 합쳐져 있음.
        findings.push(...cb.findings);
        provenanceExtra.push({ name: "콤보리스트 (ProxyNova COMB)", kind: "breach", endpoint: "api.proxynova.com /comb", count: cb.count, scannedAt: nowIso });
        if (cb.hosts.length) {
          provenanceExtra.push({ name: "Hudson Rock Cavalier (COMB 계정 교차)", kind: "breach", endpoint: "cavalier.hudsonrock.com /search-by-email", count: cb.hosts.length, scannedAt: nowIso });
        }
        infostealerHosts = [...infostealerHosts, ...cb.hosts]; // 유출∩인포스틸러 교차 호스트
      }
    }
    // 공개 소스코드 수동 큐레이션 노출 (data/security/source_code_exposures.json 미러) → breach_findings
    {
      const sc = await collectCuratedExposures(nowIso);
      if (sc.count) { findings.push(...sc.findings); provenanceExtra.push({ name: "공개 소스코드 점검 (수동 큐레이션)", kind: "breach", endpoint: "data/security/source_code_exposures.json", count: sc.count, scannedAt: nowIso }); }
    }
    } catch (e) {
      note = (note ? note + " | " : "") + `보조 소스 일부 실패: ${(e as Error).message}`;
    }

    // 중복 제거(같은 finding_id 는 먼저 본 것 유지) + is_new
    const byId = new Map<string, RawFinding>();
    for (const f of findings) if (!byId.has(f.finding_id)) byId.set(f.finding_id, f);
    findings = [...byId.values()];
    const existing = await sbGetExistingIds();
    for (const f of findings) f.is_new = !existing.has(f.finding_id);
  }

  // 적재 (정상 스캔만 DB 갱신; 오류 시 기존 데이터 보존)
  if (status === "ok") {
    try {
      // PostgREST 벌크 upsert 는 모든 행의 키 집합이 동일해야 함(PGRST102) → 고정 컬럼으로 정규화.
      const rows = findings.map((f) => ({
        finding_id: f.finding_id,
        account_masked: f.account_masked,
        account: f.account ?? null,
        domain: f.domain,
        breach_name: f.breach_name,
        breach_title: f.breach_title ?? null,
        breach_date: f.breach_date ?? null,
        data_classes: f.data_classes ?? [],
        severity: f.severity,
        is_new: f.is_new,
        discovered_at: f.discovered_at,
        source: f.source ?? null,
        password_risk: f.password_risk ?? null,
        industry: f.industry ?? null,
        reference_url: f.reference_url ?? null,
        breach_logo: f.breach_logo ?? null,
        last_scan_tag: scanTag,
      }));
      await sbUpsert(rows);
      await sbDeleteStale(scanTag);
    } catch (e) {
      status = "error";
      note = (note ? note + " | " : "") + `적재 실패: ${(e as Error).message}`;
    }
  }

  // 다크웹 인포스틸러 — 도메인 전수 (Hudson Rock Cavalier, 무료) — breach 오류와 무관하게 시도
  let infostealer: Infostealer[] = [];
  const cavalierDomains = MONITORED_DOMAINS.length ? MONITORED_DOMAINS : [...new Set(findings.map((f) => f.domain))];
  if (cavalierDomains.length) {
    infostealer = await collectCavalier(cavalierDomains, nowIso);
    await sbUpsertInfostealer(infostealer);
  }

  // 감염 호스트 상세 적재 (006) — 정상 스캔 + 계정 수집했을 때만(없으면 stale 정리로 비움)
  if (status === "ok" && HUDSONROCK_OSINT && (MONITORED_EMAILS.length || MONITORED_DOMAINS.length)) {
    // host_id 중복 제거(명부 + COMB 계정에서 같은 호스트가 나올 수 있음) 후 적재.
    const dedupHosts = [...new Map(infostealerHosts.map((h) => [h.host_id, h])).values()];
    const hostRows = dedupHosts.map((h) => ({ ...h, last_scan_tag: scanTag }));
    await sbUpsertInfostealerHosts(hostRows);
    await sbDeleteStaleHosts(scanTag);
  }

  const summary = { critical: 0, high: 0, medium: 0, low: 0 };
  let newCount = 0;
  for (const f of findings) { summary[f.severity as keyof typeof summary]++; if (f.is_new) newCount++; }

  // 수집 출처 기록 (provenance)
  const infTotal = infostealer.reduce((s, i) => s + i.total, 0);
  const sources = [
    { name: source, kind: "breach", endpoint: HIBP_API_KEY ? "haveibeenpwned.com /api/v3/breacheddomain" : (MONITORED_EMAILS.length ? "api.xposedornot.com /v1/check-email" : "(none)"), count: primaryCount, scannedAt: nowIso },
    ...provenanceExtra,
  ];
  if (infostealer.length) {
    sources.push({ name: "Hudson Rock Cavalier", kind: "infostealer", endpoint: "cavalier.hudsonrock.com /search-by-domain", count: infTotal, scannedAt: nowIso });
  }

  await sbInsertScanRun({
    scanned_at: nowIso, source, status, is_demo: false,
    total: findings.length, new_count: newCount,
    critical: summary.critical, high: summary.high, medium: summary.medium, low: summary.low,
    domains: [...new Set([...MONITORED_DOMAINS, ...findings.map((f) => f.domain)])],
    sources, note,
  });

  // 관제 알림 — 신규 유출 또는 스캔 이상 시 통지(웹훅 미설정이면 skip)
  await maybeNotify({ status, newCount, total: findings.length, summary, infTotal, note });

  return new Response(JSON.stringify({
    ok: status !== "error", status, source, total: findings.length, newCount, summary,
    infostealer: { domains: infostealer.length, total: infTotal }, infostealerHosts: infostealerHosts.length, sources, note,
  }), { headers: { "Content-Type": "application/json" } });
});

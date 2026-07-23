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
const GITLAB_TOKEN = Deno.env.get("GITLAB_TOKEN")?.trim();
const GITLAB_API = "https://gitlab.com/api/v4";

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

// ── 금융 고객 개인정보(PII) 노출 분류기 ───────────────────────────────────────
// 공개 소스코드/유출 텍스트에서 CI·DI·주민번호·카드·계좌 등 '카테고리'만 탐지한다.
// ⚠️ 실제 값은 절대 반환·저장·로그하지 않는다(PIPA·신용정보법·전자금융감독규정). 정규식 판정 후
//    매칭 값은 즉시 폐기하고 카테고리·건수·최고심각도만 돌려준다(값은 이 함수 밖으로 안 나감).
const PII_SEV_RANK: Record<string, number> = { low: 0, medium: 1, high: 2, critical: 3 };
function luhnValid(digits: string): boolean {
  let sum = 0, alt = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (d < 0 || d > 9) return false;
    if (alt) { d *= 2; if (d > 9) d -= 9; }
    sum += d; alt = !alt;
  }
  return sum % 10 === 0;
}
function rrnValid(d13: string): boolean {
  if (!/^\d{13}$/.test(d13)) return false;
  const w = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5];
  let sum = 0;
  for (let i = 0; i < 12; i++) sum += (d13.charCodeAt(i) - 48) * w[i];
  return ((11 - (sum % 11)) % 10) === (d13.charCodeAt(12) - 48);
}
function classifyFinancialPii(text: string): { categories: string[]; count: number; maxSeverity: string | null; locations: { category: string; lines: number[] }[] } {
  if (!text || typeof text !== "string") return { categories: [], count: 0, maxSeverity: null, locations: [] };
  const t = text.length > 200000 ? text.slice(0, 200000) : text;
  // 개행 오프셋 사전계산 → 매치 index 를 라인번호로 변환. 값·주변문맥은 저장 안 함(라인 위치만).
  const nl: number[] = [];
  for (let i = 0; i < t.length; i++) if (t.charCodeAt(i) === 10) nl.push(i);
  const lineOf = (idx: number) => { let lo = 0, hi = nl.length; while (lo < hi) { const mid = (lo + hi) >> 1; if (nl[mid] < idx) lo = mid + 1; else hi = mid; } return lo + 1; };
  const LINES_PER_CAT = 8; // 카테고리별 저장 라인 상한(JSON 경량화)
  const found = new Map<string, { count: number; severity: string; lines: Set<number> }>();
  const add = (label: string, severity: string, lines: number[]) => {
    if (!lines.length) return;
    const e = found.get(label) || { count: 0, severity, lines: new Set<number>() };
    e.count += lines.length;
    if (PII_SEV_RANK[severity] > PII_SEV_RANK[e.severity]) e.severity = severity;
    for (const ln of lines) if (e.lines.size < LINES_PER_CAT) e.lines.add(ln);
    found.set(label, e);
  };
  // 키워드 게이팅 계열 — 매치 라인 수집(값 미보관).
  const collectGated = (re: RegExp, label: string, severity: string) => {
    let m: RegExpExecArray | null; const lines: number[] = [];
    while ((m = re.exec(t)) !== null) lines.push(lineOf(m.index));
    add(label, severity, lines);
  };
  // 주민등록번호/외국인등록번호 — 날짜검증 정규식 + 모듈러11 체크섬(자체검증)
  { const re = /\b(\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01]))-?([1-8]\d{6})\b/g; let m: RegExpExecArray | null; const lines: number[] = [];
    while ((m = re.exec(t)) !== null) { if (rrnValid(m[1] + m[2])) lines.push(lineOf(m.index)); } add("주민등록번호/외국인등록번호", "critical", lines); }
  // 카드번호 — 16자리(구분자 허용) + Luhn(자체검증)
  { const re = /\b(?:\d[ -]?){15}\d\b/g; let m: RegExpExecArray | null; const lines: number[] = [];
    while ((m = re.exec(t)) !== null) { const d = m[0].replace(/[ -]/g, ""); if (d.length === 16 && luhnValid(d)) lines.push(lineOf(m.index)); } add("신용/체크카드번호", "critical", lines); }
  // CI(연계정보) — 키워드 게이팅 + 88자 base64(== 패딩)
  collectGated(/(?:\bci\b|unique_key|connecting_info(?:rmation)?|연계정보)["'\s]*[:=]["'\s]*[A-Za-z0-9+/]{86}==/gi, "CI(연계정보)", "critical");
  // DI(중복가입확인정보) — 키워드 게이팅(길이 미확정→키워드 필수)
  collectGated(/(?:\bdi\b|unique_in_site|dupinfo|duplicate_info|중복가입)["'\s]*[:=]["'\s]*[A-Za-z0-9+/]{64,86}={0,2}/gi, "DI(중복가입확인정보)", "critical");
  // 여권 — 키워드 게이팅
  collectGated(/(?:passport|여권)["'\s:=]*[A-Za-z]\d{8}\b/gi, "여권번호", "high");
  // 운전면허 — 키워드 게이팅
  collectGated(/(?:license|운전면허|면허번호)["'\s:=]*\d{2}-?\d{2}-?\d{6}-?\d{2}\b/gi, "운전면허번호", "high");
  // 은행계좌 — 키워드/은행명 게이팅 + 자릿수(10~14)
  { const re = /(?:계좌|account|입금|이체|국민은행|신한은행|우리은행|하나은행|농협|기업은행|전북은행|광주은행)["'\s:=]*(\d{2,6}[- ]?\d{2,6}[- ]?\d{1,6})\b/gi; let m: RegExpExecArray | null; const lines: number[] = [];
    while ((m = re.exec(t)) !== null) { const d = m[1].replace(/[- ]/g, ""); if (d.length >= 10 && d.length <= 14 && !(d.length === 11 && /^01[016789]/.test(d))) lines.push(lineOf(m.index)); } add("은행계좌번호", "high", lines); }
  // 휴대전화
  collectGated(/\b01[016789][- ]?\d{3,4}[- ]?\d{4}\b/g, "휴대전화번호", "medium");
  // 이메일 — 예시/플레이스홀더 도메인·로컬 제외(코드 예시 노이즈 억제)
  { const re = /[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}/g; let m: RegExpExecArray | null; const lines: number[] = [];
    while ((m = re.exec(t)) !== null) { const e = m[0].toLowerCase(); const dm = e.split("@")[1] || "";
      if (/@(example|test|sample|domain|email|localhost|yourdomain|company|acme|foo|bar)\./.test(e)) continue;
      if (/\.(example|test|invalid|local)$/.test(dm)) continue;
      if (/^(you|your[_-]?email|user|username|name|someone|admin|test|example|noreply|no-reply|email|first\.last)@/.test(e)) continue;
      lines.push(lineOf(m.index)); }
    add("이메일", "medium", lines); }
  // 주소 — 시도 + 시군구 + 동/로/길(범용 한글문장 억제)
  collectGated(/(서울|부산|대구|인천|광주|대전|울산|세종|경기|강원|충북|충남|전북|전남|경북|경남|제주)(?:특별시|광역시|특별자치시|특별자치도|도)?\s*[가-힣]{2,}(?:시|군|구)\s*[가-힣0-9]+(?:읍|면|동|가|로|길)/g, "주소", "medium");
  // 생년월일 — 키워드 게이팅
  collectGated(/(생년월일|생일|출생|dob|birth\s*date|birthdate)["'\s:=]*(?:\d{4}[-.\/]\d{1,2}[-.\/]\d{1,2}|\d{2}[-.\/]\d{1,2}[-.\/]\d{1,2})/gi, "생년월일", "medium");
  // 성명 — 키워드 게이팅(한글 성명 2~4자)
  collectGated(/(성명|이름|고객명|수취인|예금주|가입자명|\bname\b)["'\s:=]+[가-힣]{2,4}(?![가-힣])/gi, "성명", "medium");
  const categories = [...found.keys()];
  const locations = [...found.entries()].map(([category, e]) => ({ category, lines: [...e.lines].sort((a, b) => a - b) }));
  let maxSeverity: string | null = null, count = 0;
  for (const [, e] of found) { count += e.count; if (!maxSeverity || PII_SEV_RANK[e.severity] > PII_SEV_RANK[maxSeverity]) maxSeverity = e.severity; }
  return { categories, count, maxSeverity, locations };
}

// 파일 경로/이름 자체에 박힌 고신뢰 식별·금융 값(주민/외국인등록번호·카드·휴대전화)을 마스킹한다.
// breach_title·reference_url 은 값 미저장 원칙의 사각지대였다 — 파일명에 값이 있으면 제목/URL 로 그대로 저장됨.
// 파일명은 값이 밑줄·문자에 바로 붙는 경우가 많아(예: customers_9001011234567.csv) 정규식 \b 로는
// 못 잡는다 → 최대 숫자런을 추출(내부 단일 '-'/공백 허용)해 길이·체크섬으로 판정한다. 프런트 redactPii 와 동일 알고리즘.
function redactPiiInPath(s: string): { text: string; redacted: boolean } {
  if (!s) return { text: s, redacted: false };
  const isD = (c: number) => c >= 48 && c <= 57;
  const classify = (d: string): string | null => {
    if (d.length === 13 && rrnValid(d) && ((): boolean => { const mm = +d.slice(2, 4), dd = +d.slice(4, 6), g = +d.charAt(6); return mm >= 1 && mm <= 12 && dd >= 1 && dd <= 31 && g >= 1 && g <= 8; })()) return "[식별번호]";
    if (d.length === 16 && luhnValid(d)) return "[카드번호]";
    if ((d.length === 10 || d.length === 11) && d.charCodeAt(0) === 48 && d.charCodeAt(1) === 49 && "016789".indexOf(d.charAt(2)) >= 0) return "[전화번호]";
    return null;
  };
  let out = "", redacted = false, i = 0;
  const n = s.length;
  while (i < n) {
    if (!isD(s.charCodeAt(i))) { out += s.charAt(i); i++; continue; }
    let j = i, digits = "";
    while (j < n) {
      const c = s.charCodeAt(j);
      if (isD(c)) { digits += s.charAt(j); j++; continue; }
      if ((c === 45 || c === 32) && j + 1 < n && isD(s.charCodeAt(j + 1))) { j++; continue; }
      break;
    }
    const label = classify(digits);
    if (label) { out += label; redacted = true; } else { out += s.slice(i, j); }
    i = j;
  }
  return { text: out, redacted };
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
  // 검색 쿼리: 자격증명 + 개인정보(주민번호·연계정보) 맥락으로 확장. 검색은 넓게(재현율↑),
  // 실제 PII 판정 정밀도는 파일 내용 분류기(classifyFinancialPii)가 담보한다.
  const GH_QUERIES = [
    { term: "password", dc: ["공개 코드 노출", "자격증명 의심"], useAt: true },
    { term: "주민번호", dc: ["공개 코드 노출", "개인정보 의심"], useAt: false },
    { term: "연계정보", dc: ["공개 코드 노출", "개인정보 의심"], useAt: false },
    { term: "계좌번호", dc: ["공개 코드 노출", "개인정보 의심"], useAt: false },
    { term: "여권번호", dc: ["공개 코드 노출", "개인정보 의심"], useAt: false },
  ];
  const SEARCH_LIMIT = 15;   // 총 코드검색 호출 상한(Edge 실행시간·레이트 보호; 상위 우선순위 커버)
  const PII_SCAN_LIMIT = 8;  // 파일 내용 스캔 상한(Edge 실행시간 보호)
  let searches = 0, scanned = 0;
  for (const gq of GH_QUERIES) {
    for (const domain of domains) {
      if (searches >= SEARCH_LIMIT) break;
      searches++;
      const q = encodeURIComponent(gq.useAt ? `"@${domain}" ${gq.term}` : `"${domain}" ${gq.term}`);
      const r = await fetchJson(`${GITHUB_API}/search/code?q=${q}&per_page=15`, { headers }, { retries: 1, baseDelay: 2000 });
      // deno-lint-ignore no-explicit-any
      const items: any[] = Array.isArray(r.data?.items) ? r.data.items : [];
      for (const it of items) {
        const repo = it.repository?.full_name || "";
        const path = it.path || "";
        const url = it.html_url || "";
        const key = `${repo}/${path}`;
        if (!repo || seen.has(key)) continue;
        seen.add(key);
        // 파일명/경로 자체에 박힌 식별·금융 값 마스킹(값 미저장 불변식). 값 포함 시 파일 URL 대신 레포 루트로.
        const red = redactPiiInPath(`${repo} · ${path}`);
        const breachTitle = red.text.slice(0, 120);
        const safeUrl = red.redacted ? `https://github.com/${repo}` : url;
        findings.push(await mkRawFinding({
          domain, alias: "*",
          breachName: "GitHub 공개 노출",
          breachTitle,
          dataClassesKo: gq.dc,
          severity: "high",
          source: "공개 노출 (GitHub)",
          referenceUrl: safeUrl,
        }, nowIso, key));
        // 파일 내용 스캔 → 금융 고객 PII 카테고리 탐지(값 미저장). 상한 내에서만.
        if (scanned < PII_SCAN_LIMIT && it.url) {
          scanned++;
          try {
            const rawRes = await fetchT(it.url, { headers: { ...headers, Accept: "application/vnd.github.raw" } }, 8000);
            if (rawRes.ok) {
              const pii = classifyFinancialPii(await rawRes.text());
              if (pii.categories.length) {
                findings.push(await mkRawFinding({
                  domain, alias: "*",
                  breachName: "고객 개인정보 노출 (GitHub)",
                  breachTitle, // 파일명 마스킹 재사용(위에서 계산)
                  dataClassesKo: pii.categories, // 카테고리만 — 실제 값 미포함
                  severity: pii.maxSeverity || "high",
                  source: "고객정보 노출 (GitHub)",
                  referenceUrl: safeUrl, // 파일명에 값 있으면 레포 루트(딥링크 대신)
                  piiLocations: pii.locations, // 카테고리별 라인 위치(값 미포함)
                }, nowIso, `pii|${key}`));
              }
            }
          } catch { /* 내용 스캔 실패는 무시(포인터 finding 은 유지) */ }
          await sleep(300);
        }
      }
      await sleep(1000); // 코드 검색 레이트리밋 배려(Edge 실행시간 한계 고려 — 쿼리 늘어 축소)
    }
    if (searches >= SEARCH_LIMIT) break;
  }
  return { findings, used: true, count: findings.length };
}

// ── GitLab 공개 노출 검색 (키-게이트, 무료 합법) → breach_findings ───────────
// GitLab 은 GitHub 처럼 토큰리스 전역 코드검색 API 가 없어 GITLAB_TOKEN(read_api) 필요.
// gitlab.com 은 고급검색(Elasticsearch) 활성이라 토큰으로 scope=blobs 전역 검색이 동작한다.
// 값은 저장하지 않고 레포/파일 포인터만 finding 으로 남긴다(GitHub 수집기와 동일 정책).
async function collectGitlab(domains: string[], nowIso: string): Promise<{ findings: RawFinding[]; used: boolean; count: number }> {
  if (!GITLAB_TOKEN) return { findings: [], used: false, count: 0 };
  const headers = { "PRIVATE-TOKEN": GITLAB_TOKEN };
  const findings: RawFinding[] = [];
  const seen = new Set<string>();
  const projPath = new Map<number, string>(); // project_id → path_with_namespace (URL 구성용 캐시)
  const GL_QUERIES = [
    { term: "password", dc: ["공개 코드 노출", "자격증명 의심"], useAt: true },
    { term: "주민번호", dc: ["공개 코드 노출", "개인정보 의심"], useAt: false },
    { term: "계좌번호", dc: ["공개 코드 노출", "개인정보 의심"], useAt: false },
  ];
  const SEARCH_LIMIT = 12; // 총 검색 호출 상한(Edge 실행시간·레이트 보호)
  let searches = 0;
  for (const gq of GL_QUERIES) {
    for (const domain of domains) {
      if (searches >= SEARCH_LIMIT) break;
      searches++;
      const term = gq.useAt ? `"@${domain}" ${gq.term}` : `"${domain}" ${gq.term}`;
      const q = encodeURIComponent(term);
      const r = await fetchJson(`${GITLAB_API}/search?scope=blobs&search=${q}&per_page=15`, { headers }, { retries: 1, baseDelay: 2000 });
      // deno-lint-ignore no-explicit-any
      const items: any[] = Array.isArray(r.data) ? r.data : [];
      for (const it of items) {
        const pid = Number(it.project_id);
        const path = it.path || it.filename || "";
        if (!pid || !path) continue;
        const key = `gl:${pid}/${path}`;
        if (seen.has(key)) continue;
        seen.add(key);
        // 프로젝트 web 경로 조회(캐시) → blob URL 구성. 실패 시 검색 링크로 대체.
        let webPath = projPath.get(pid);
        if (webPath === undefined) {
          try {
            const pr = await fetchJson(`${GITLAB_API}/projects/${pid}`, { headers }, { retries: 0, baseDelay: 1000 });
            webPath = (pr.data?.path_with_namespace as string) || "";
          } catch { webPath = ""; }
          projPath.set(pid, webPath);
        }
        const ref = it.ref || "master";
        const url = webPath ? `https://gitlab.com/${webPath}/-/blob/${ref}/${path}` : `https://gitlab.com/search?scope=blobs&search=${q}`;
        const rawTitle = webPath ? `${webPath} · ${path}` : `project#${pid} · ${path}`;
        // 파일명/경로 자체의 식별·금융 값 마스킹. 값 포함 시 blob URL 대신 프로젝트 루트/검색 링크로.
        const red = redactPiiInPath(rawTitle);
        const title = red.text.slice(0, 120);
        const safeUrl = red.redacted ? (webPath ? `https://gitlab.com/${webPath}` : `https://gitlab.com/search?scope=blobs&search=${q}`) : url;
        findings.push(await mkRawFinding({
          domain, alias: "*",
          breachName: "GitLab 공개 노출",
          breachTitle: title,
          dataClassesKo: gq.dc,
          severity: "high",
          source: "공개 노출 (GitLab)",
          referenceUrl: safeUrl,
        }, nowIso, key));
      }
      await sleep(1000); // 코드 검색 레이트리밋 배려
    }
    if (searches >= SEARCH_LIMIT) break;
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
  // 개인정보 노출 위치 — 카테고리별 라인번호(값·문맥 미저장). GitHub 딥링크(url#L<line>)용.
  pii_locations?: { category: string; lines: number[] }[];
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
  o: { domain: string; alias: string; breachName: string; breachTitle?: string; breachDate?: string; dataClassesKo: string[]; severity: string; source: string; referenceUrl?: string; piiLocations?: { category: string; lines: number[] }[] },
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
    pii_locations: o.piiLocations,
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
// 영속 first-seen(016). is_new 를 breach_findings(churn) 대신 finding_seen(append-only) 기준으로.
async function sbGetSeenIds(): Promise<Set<string>> {
  const res = await fetchT(`${SUPABASE_URL}/rest/v1/finding_seen?select=finding_id&limit=100000`, { headers: sbHeaders });
  if (!res.ok) return new Set();
  const rows = await res.json();
  return new Set(rows.map((r: { finding_id: string }) => r.finding_id));
}
async function sbInsertSeen(ids: string[]) {
  const uniq = [...new Set(ids)].filter(Boolean);
  if (!uniq.length) return;
  const res = await fetchT(`${SUPABASE_URL}/rest/v1/finding_seen?on_conflict=finding_id`, {
    method: "POST",
    headers: { ...sbHeaders, Prefer: "resolution=ignore-duplicates,return=minimal" },
    body: JSON.stringify(uniq.map((finding_id) => ({ finding_id }))),
  });
  if (!res.ok) console.warn(`finding_seen insert HTTP ${res.status}`);
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

// ── 보안 뉴스 수집 (Google News RSS, 무료·키불요·서버사이드=CORS 무관) → security_news ──
// 금융·보안 이슈를 매일 배치로 수집해 대시보드 '오늘의 보안 뉴스'에 노출(담당자 아침 참고용).
// 비민감 공개 뉴스 링크만 저장. 유출 스캔 본체와 완전 격리(자체 timeout + 호출부 try/catch).
const NEWS_QUERIES: { q: string; cat: string; finance: boolean }[] = [
  { q: "금융 보안", cat: "금융보안", finance: true },
  { q: "은행 해킹 유출", cat: "금융보안", finance: true },
  { q: "개인정보 유출", cat: "개인정보", finance: false },
  { q: "랜섬웨어", cat: "랜섬웨어", finance: false },
  { q: "다크웹", cat: "다크웹", finance: false },
  { q: "사이버 공격", cat: "사이버공격", finance: false },
  { q: "보안 취약점 제로데이", cat: "취약점", finance: false },
];
const NEWS_FINANCE_RE = /금융|은행|카드사|증권|보험|핀테크|캐피탈|저축은행|가상자산|암호화폐|코인|거래소|간편결제|페이|대출|투자|자산운용|JB금융|전북은행|광주은행|우리금융|우리은행/;
function newsDecodeEntities(s: string): string {
  return s.replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#0?39;/g, "'").replace(/&apos;/g, "'").replace(/&amp;/g, "&");
}
function newsXmlTag(block: string, name: string): string {
  const start = block.indexOf("<" + name);
  if (start < 0) return "";
  const gt = block.indexOf(">", start);
  const end = block.indexOf("</" + name + ">", gt);
  if (gt < 0 || end < 0) return "";
  const v = block.slice(gt + 1, end).replace(/^<!\[CDATA\[/, "").replace(/\]\]>$/, "");
  return newsDecodeEntities(v.trim());
}
interface NewsRow { news_id: string; title: string; url: string; source: string; category: string; is_finance: boolean; published_at: string | null; }
async function collectSecurityNews(): Promise<{ rows: NewsRow[]; count: number }> {
  const seen = new Set<string>();
  const rows: NewsRow[] = [];
  await Promise.allSettled(NEWS_QUERIES.map(async (gq) => {
    const url = `https://news.google.com/rss/search?q=${encodeURIComponent(gq.q)}&hl=ko&gl=KR&ceid=KR:ko`;
    const res = await fetchT(url, { headers: { "User-Agent": "Mozilla/5.0 (compatible; darkweb-monitor)" } }, 8000);
    if (!res.ok) return;
    const xml = await res.text();
    const parts = xml.split("<item>");
    let taken = 0;
    for (let i = 1; i < parts.length && taken < 12; i++) {
      const b = parts[i].split("</item>")[0];
      const rawTitle = newsXmlTag(b, "title");
      const link = newsXmlTag(b, "link");
      if (!rawTitle || !link) continue;
      const li = rawTitle.lastIndexOf(" - "); // Google 뉴스는 "제목 - 매체" 형식
      const title = (li > 0 ? rawTitle.slice(0, li) : rawTitle).trim();
      const source = (li > 0 ? rawTitle.slice(li + 3) : newsXmlTag(b, "source")).trim();
      const pub = newsXmlTag(b, "pubDate");
      let publishedAt: string | null = null;
      if (pub) { const d = new Date(pub); if (!isNaN(d.getTime())) publishedAt = d.toISOString(); }
      const idPart = link.split("/articles/")[1]?.split("?")[0] || "";
      const news_id = (idPart || title).slice(0, 200);
      if (!title || seen.has(news_id)) continue;
      seen.add(news_id);
      rows.push({
        news_id, title: title.slice(0, 300), url: link, source: source.slice(0, 80),
        category: gq.cat, is_finance: gq.finance || NEWS_FINANCE_RE.test(title), published_at: publishedAt,
      });
      taken++;
    }
  }));
  return { rows, count: rows.length };
}
async function sbUpsertNews(rows: NewsRow[]) {
  if (!rows.length) return;
  const fetchedAt = new Date().toISOString();
  const res = await fetchT(`${SUPABASE_URL}/rest/v1/security_news?on_conflict=news_id`, {
    method: "POST",
    headers: { ...sbHeaders, Prefer: "resolution=merge-duplicates,return=minimal" },
    body: JSON.stringify(rows.map((r) => ({ ...r, fetched_at: fetchedAt }))),
  });
  if (!res.ok) throw new Error(`security_news upsert HTTP ${res.status} ${(await res.text()).slice(0, 150)}`);
}
async function sbPruneNews() {
  // 14일간 재수집 안 된 뉴스 정리(테이블 경량 유지). fetched_at 기준(매 배치 갱신 + NOT NULL)이라
  // published_at 이 NULL 인 행도 반드시 회수된다(published_at 기준이면 NULL<cutoff=unknown 으로 영구 잔존).
  const cutoff = new Date(Date.now() - 14 * 86400000).toISOString();
  const res = await fetchT(`${SUPABASE_URL}/rest/v1/security_news?fetched_at=lt.${cutoff}`, {
    method: "DELETE", headers: { ...sbHeaders, Prefer: "return=minimal" },
  });
  if (!res.ok) console.warn(`security_news prune HTTP ${res.status}`);
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
  let prevBreachCount = 0; // 직전 breach_findings 건수 — 부분 스캔 가드용(stale-delete 스킵 판단)

  // 보안 뉴스 — 유출 스캔과 병렬 실행(네트워크 대기 겹쳐 월클록 추가 최소화). 완전 격리(자체 catch).
  let newsErr = "";
  const newsTask: Promise<number> = (async () => {
    try {
      const news = await collectSecurityNews();
      if (!news.count) return 0;
      await sbUpsertNews(news.rows);
      await sbPruneNews();
      return news.count;
    } catch (e) { newsErr = (e as Error).message; return 0; }
  })();

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

    try { // 보조 소스 오케스트레이션 (개별 실패는 격리)
    // ── 보조 소스 병렬 수집 ─────────────────────────────────────────────────
    // 각 소스는 독립(같은 도메인/계정을 서로 다른 API로 조회)이라 병렬 실행한다.
    // 순차 await 가 Edge Function 월클록(≤150s)을 넘겨 배치가 죽던 문제를 해소.
    // JS 단일스레드 → findings/provenanceExtra push·infostealerHosts concat 은
    // 각각 동기 단일문이라 await 사이에서만 양보, 인터리브 레이스 없음.
    const auxErrors: string[] = [];
    const runAux = async (label: string, fn: () => Promise<void>) => {
      try { await fn(); } catch (e) { auxErrors.push(`${label}: ${(e as Error).message}`); }
    };
    // 병렬 배치: 서로 다른 호스트만 호출하는 6종(호스트 경합 없음).
    const auxTasks: Promise<void>[] = [];
    // IntelX (도메인 전수, 키-게이트) → 2.intelx.io
    if (INTELX_API_KEY && MONITORED_DOMAINS.length) auxTasks.push(runAux("IntelX", async () => {
      const ix = await collectIntelx(MONITORED_DOMAINS, nowIso);
      if (ix.used) { findings.push(...ix.findings); provenanceExtra.push({ name: "Intelligence X", kind: "breach", endpoint: "2.intelx.io /intelligent/search", count: ix.count, scannedAt: nowIso }); }
    }));
    // LeakCheck (키 있으면 도메인 v2, 없으면 무료 public 계정별) → leakcheck.io
    if (LEAKCHECK_API_KEY ? MONITORED_DOMAINS.length : MONITORED_EMAILS.length) auxTasks.push(runAux("LeakCheck", async () => {
      const lc = await collectLeakcheck(MONITORED_DOMAINS, MONITORED_EMAILS, nowIso);
      if (lc.used) { findings.push(...lc.findings); provenanceExtra.push({ name: lc.mode === "v2-domain" ? "LeakCheck" : "LeakCheck (public)", kind: "breach", endpoint: lc.mode === "v2-domain" ? "leakcheck.io /api/v2/query?type=domain" : "leakcheck.io /api/public", count: lc.count, scannedAt: nowIso }); }
    }));
    // Hudson Rock 계정별 인포스틸러 (무료) → cavalier.hudsonrock.com
    if (HUDSONROCK_OSINT && MONITORED_EMAILS.length) auxTasks.push(runAux("Cavalier", async () => {
      const hr = await collectCavalierAccounts(MONITORED_EMAILS, nowIso);
      infostealerHosts = infostealerHosts.concat(hr.hosts);
      if (hr.findings.length) { findings.push(...hr.findings); provenanceExtra.push({ name: "Hudson Rock Cavalier (계정별)", kind: "breach", endpoint: "cavalier.hudsonrock.com /search-by-email", count: hr.findings.length, scannedAt: nowIso }); }
    }));
    // GitHub 공개 노출 (키-게이트, 무료 합법 크롤링) → api.github.com
    if (GITHUB_TOKEN && MONITORED_DOMAINS.length) auxTasks.push(runAux("GitHub", async () => {
      const gh = await collectGithub(MONITORED_DOMAINS, nowIso);
      if (gh.used) { findings.push(...gh.findings); provenanceExtra.push({ name: "공개 노출 (GitHub)", kind: "breach", endpoint: "api.github.com /search/code", count: gh.count, scannedAt: nowIso }); }
    }));
    // GitLab 공개 노출 (키-게이트, 무료 합법, 포인터만) → gitlab.com
    if (GITLAB_TOKEN && MONITORED_DOMAINS.length) auxTasks.push(runAux("GitLab", async () => {
      const gl = await collectGitlab(MONITORED_DOMAINS, nowIso);
      if (gl.used) { findings.push(...gl.findings); provenanceExtra.push({ name: "공개 노출 (GitLab)", kind: "breach", endpoint: "gitlab.com /api/v4/search", count: gl.count, scannedAt: nowIso }); }
    }));
    // 공개 소스코드 수동 큐레이션 노출 (정적 미러, 네트워크 없음)
    auxTasks.push(runAux("Curated", async () => {
      const sc = await collectCuratedExposures(nowIso);
      if (sc.count) { findings.push(...sc.findings); provenanceExtra.push({ name: "공개 소스코드 점검 (수동 큐레이션)", kind: "breach", endpoint: "data/security/source_code_exposures.json", count: sc.count, scannedAt: nowIso }); }
    }));
    await Promise.allSettled(auxTasks);
    // ProxyNova COMB 는 내부에서 leakcheck.io·cavalier.hudsonrock.com 를 재호출한다 → 위 배치의
    // LeakCheck·Cavalier 태스크와 같은 호스트. 동시 실행 시 그 두 호스트에 스트림이 겹쳐 429 →
    // 재시도로 월클록이 예측불가해짐. 배치 완료 후 단독 순차 실행으로 경합 제거(호스트 경합 0).
    if (MONITORED_DOMAINS.length) await runAux("ProxyNova", async () => {
      const cb = await collectProxynovaComb(MONITORED_DOMAINS, nowIso);
      if (cb.used) {
        // cb.findings 에는 COMB + 유출이력(LeakCheck/XON) + 인포스틸러 교차가 병렬수집되어 합쳐져 있음.
        findings.push(...cb.findings);
        provenanceExtra.push({ name: "콤보리스트 (ProxyNova COMB)", kind: "breach", endpoint: "api.proxynova.com /comb", count: cb.count, scannedAt: nowIso });
        if (cb.hosts.length) {
          provenanceExtra.push({ name: "Hudson Rock Cavalier (COMB 계정 교차)", kind: "breach", endpoint: "cavalier.hudsonrock.com /search-by-email", count: cb.hosts.length, scannedAt: nowIso });
        }
        infostealerHosts = infostealerHosts.concat(cb.hosts); // 유출∩인포스틸러 교차 호스트
      }
    });
    if (auxErrors.length) note = (note ? note + " | " : "") + `보조 소스 일부 실패: ${auxErrors.join("; ")}`;
    } catch (e) {
      note = (note ? note + " | " : "") + `보조 소스 오케스트레이션 실패: ${(e as Error).message}`;
    }

    // 중복 제거(같은 finding_id 는 먼저 본 것 유지) + is_new
    const byId = new Map<string, RawFinding>();
    for (const f of findings) if (!byId.has(f.finding_id)) byId.set(f.finding_id, f);
    findings = [...byId.values()];
    prevBreachCount = (await sbGetExistingIds()).size;  // 부분 스캔 가드용(직전 DB 건수)
    const seen = await sbGetSeenIds();                    // is_new 판정용(영속)
    for (const f of findings) f.is_new = !seen.has(f.finding_id);
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
        pii_locations: f.pii_locations ?? null,
        last_scan_tag: scanTag,
      }));
      await sbUpsert(rows);
      await sbInsertSeen(findings.map((f) => f.finding_id)); // 영속 first-seen 갱신(is_new 안정화)
      // 부분 스캔(직전 대비 수집 급감) 의심 시 stale-delete 스킵 — 유출이 삭제됐다 재등장하며 목록 churn·신규 반복 방지.
      if (prevBreachCount === 0 || findings.length >= prevBreachCount * 0.7) {
        await sbDeleteStale(scanTag);
      } else {
        console.warn(`[scan] 부분 스캔 의심(수집 ${findings.length} < 직전 ${prevBreachCount}×0.7) — stale-delete 스킵, 기존 findings 보존`);
      }
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

  // 병렬로 시작한 뉴스 수집 완료 대기(이미 스캔과 겹쳐 실행됨).
  // ⚠️ 하드 상한 20s — fetchT 는 '헤더 수신'까지만 abort 보호하므로 본문 스트림이 정체되면
  //    newsTask 가 영영 안 끝날 수 있다. 그 hang 이 유출 스캔 응답을 인질로 잡아 함수 전체가
  //    WORKER_RESOURCE_LIMIT/타임아웃으로 죽는 것을 막는다(초과 시 이번 배치 뉴스만 건너뜀).
  const newsCount = await Promise.race([
    newsTask,
    new Promise<number>((resolve) => setTimeout(() => resolve(0), 20000)),
  ]);
  if (newsErr) note = (note ? note + " | " : "") + `보안 뉴스 수집 실패: ${newsErr}`;

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
  if (newsCount) {
    sources.push({ name: "보안 뉴스 (Google News)", kind: "news", endpoint: "news.google.com /rss/search", count: newsCount, scannedAt: nowIso });
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
    infostealer: { domains: infostealer.length, total: infTotal }, infostealerHosts: infostealerHosts.length, news: newsCount, sources, note,
  }), { headers: { "Content-Type": "application/json" } });
});

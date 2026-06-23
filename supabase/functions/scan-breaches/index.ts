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

// 견고한 JSON fetch: 429/5xx 는 Retry-After/지수 백오프로 재시도. 실패해도 throw 안 함.
// deno-lint-ignore no-explicit-any
async function fetchJson(url: string, init: { headers?: Record<string, string>; method?: string; body?: string } = {}, opts: { retries?: number; baseDelay?: number } = {}): Promise<{ ok: boolean; status: number; data: any }> {
  const { headers = {}, method = "GET", body } = init;
  const { retries = 2, baseDelay = 800 } = opts;
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const res = await fetch(url, { method, headers: { "user-agent": UA, ...headers }, body });
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
    const res = await fetch(`${XON_BASE}/breaches`, { headers: { "user-agent": UA } });
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
  } catch { return {}; }
}
async function xonCheckEmail(email: string): Promise<string[]> {
  try {
    const res = await fetch(`${XON_BASE}/check-email/${encodeURIComponent(email)}`, { headers: { "user-agent": UA } });
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
    const res = await fetch(`${HIBP_BASE}/breaches`, { headers: { "user-agent": UA } });
    if (!res.ok) return {};
    const arr = await res.json();
    const map: Catalog = {};
    for (const b of arr) map[b.Name] = { title: b.Title ?? b.Name, date: isoDate(b.BreachDate), dataClasses: b.DataClasses ?? [] };
    return map;
  } catch { return {}; }
}
async function hibpDomain(domain: string): Promise<Record<string, string[]> | null> {
  // 도메인 전수 검색 대비: 429 는 Retry-After 만큼 대기 후 재시도.
  for (let attempt = 0; attempt < 4; attempt++) {
    const res = await fetch(`${HIBP_BASE}/breacheddomain/${encodeURIComponent(domain)}`, {
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
      const res = await fetch(`${CAVALIER_BASE}/search-by-domain?domain=${encodeURIComponent(domain)}`, { headers: { "user-agent": UA } });
      if (!res.ok) continue;
      const d = await res.json();
      const urls = (d?.data?.all_urls ?? []).slice(0, 30).map((u: { url: string; type: string; occurrence: number }) => ({ url: u.url, type: u.type, occurrence: u.occurrence }));
      out.push({
        domain, source: "Hudson Rock Cavalier",
        total: d.total ?? 0, employees: d.employees ?? 0, users: d.users ?? 0,
        third_parties: d.third_parties ?? 0, affected_urls: urls, scanned_at: nowIso,
      });
      await sleep(300);
    } catch { /* skip domain */ }
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
    const r = await fetchJson(`${CAVALIER_BASE}/search-by-email?email=${encodeURIComponent(email)}`);
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
    await sleep(1000); // 무료 OSINT 공정사용 ~1 req/s
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
  const res = await fetch(`${SUPABASE_URL}/rest/v1/breach_findings?select=finding_id`, { headers: sbHeaders });
  if (!res.ok) return new Set();
  const rows = await res.json();
  return new Set(rows.map((r: { finding_id: string }) => r.finding_id));
}
async function sbUpsert(rows: unknown[]) {
  if (!rows.length) return;
  const res = await fetch(`${SUPABASE_URL}/rest/v1/breach_findings?on_conflict=finding_id`, {
    method: "POST",
    headers: { ...sbHeaders, Prefer: "resolution=merge-duplicates,return=minimal" },
    body: JSON.stringify(rows),
  });
  if (!res.ok) throw new Error(`upsert HTTP ${res.status} ${(await res.text()).slice(0, 200)}`);
}
async function sbDeleteStale(scanTag: string) {
  // 이번 스캔에서 안 본 항목(다른 tag 또는 null) 제거 = 현재 노출만 유지.
  const res = await fetch(`${SUPABASE_URL}/rest/v1/breach_findings?or=(last_scan_tag.neq.${scanTag},last_scan_tag.is.null)`, {
    method: "DELETE", headers: { ...sbHeaders, Prefer: "return=minimal" },
  });
  if (!res.ok) console.warn(`stale delete HTTP ${res.status}`);
}
async function sbInsertScanRun(run: unknown) {
  const res = await fetch(`${SUPABASE_URL}/rest/v1/scan_runs`, {
    method: "POST", headers: { ...sbHeaders, Prefer: "return=minimal" }, body: JSON.stringify(run),
  });
  if (!res.ok) console.warn(`scan_run insert HTTP ${res.status}`);
}
async function sbUpsertInfostealer(rows: Infostealer[]) {
  if (!rows.length) return;
  const res = await fetch(`${SUPABASE_URL}/rest/v1/infostealer_findings?on_conflict=domain`, {
    method: "POST",
    headers: { ...sbHeaders, Prefer: "resolution=merge-duplicates,return=minimal" },
    body: JSON.stringify(rows),
  });
  if (!res.ok) console.warn(`infostealer upsert HTTP ${res.status} ${(await res.text()).slice(0, 200)}`);
}
async function sbUpsertInfostealerHosts(rows: InfostealerHostRow[]) {
  if (!rows.length) return;
  const res = await fetch(`${SUPABASE_URL}/rest/v1/infostealer_hosts?on_conflict=host_id`, {
    method: "POST",
    headers: { ...sbHeaders, Prefer: "resolution=merge-duplicates,return=minimal" },
    body: JSON.stringify(rows),
  });
  if (!res.ok) console.warn(`infostealer_hosts upsert HTTP ${res.status} ${(await res.text()).slice(0, 200)}`);
}
async function sbDeleteStaleHosts(scanTag: string) {
  // 이번 스캔에서 안 본 호스트 제거 = 현재 모니터링 계정의 감염만 유지.
  const res = await fetch(`${SUPABASE_URL}/rest/v1/infostealer_hosts?or=(last_scan_tag.neq.${scanTag},last_scan_tag.is.null)`, {
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
      const rows = findings.map((f) => ({ ...f, last_scan_tag: scanTag }));
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
  if (status === "ok" && HUDSONROCK_OSINT && MONITORED_EMAILS.length) {
    const hostRows = infostealerHosts.map((h) => ({ ...h, last_scan_tag: scanTag }));
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

  return new Response(JSON.stringify({
    ok: status !== "error", status, source, total: findings.length, newCount, summary,
    infostealer: { domains: infostealer.length, total: infTotal }, infostealerHosts: infostealerHosts.length, sources, note,
  }), { headers: { "Content-Type": "application/json" } });
});

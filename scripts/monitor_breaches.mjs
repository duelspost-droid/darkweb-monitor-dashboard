// 다크웹/유출 계정 모니터링 수집기 (로컬/CI 실행용).
//
// 데이터 소스 우선순위:
//  1) HIBP_API_KEY 가 있으면 Have I Been Pwned 도메인 검색 API(유료, 도메인 소유검증 필요)로
//     config.domains 의 도메인 계정 유출을 전수 조회한다.
//  2) 키가 없고 config.accounts(개별 이메일)가 있으면 무료 XposedOrNot API 로
//     계정별 유출을 조회한다(키 불필요, 실데이터).
//  3) 둘 다 없으면 status="no_source" 로 수집을 건너뛴다(가짜/데모 데이터 생성 안 함).
//
// 어떤 경우에도:
//  - 평문 비밀번호·전체 이메일·기타 개인식별자는 절대 저장하지 않는다.
//  - 계정은 항상 마스킹(jo***@domain)으로만 저장한다.
//  - 다크웹 마켓/포럼을 직접 크롤링하지 않고 합법 유출 인텔리전스 API 만 사용한다.
//
// 출력:
//  - data/security/latest_breach_scan.json (원본 기록)
//  - data/security/history/breach_scan_<stamp>.json (이력)
//  - lib/data/generated/breachMonitor.ts (정적 사이트가 임포트)
//  - (선택) Supabase breach_findings 테이블 upsert

import { mkdir, readFile, writeFile } from "node:fs/promises";
import { createHash } from "node:crypto";
import { join } from "node:path";

const root = process.cwd();
const securityDir = join(root, "data", "security");
const historyDir = join(securityDir, "history");
const generatedFile = join(root, "lib", "data", "generated", "breachMonitor.ts");
const configFile = join(securityDir, "monitor_config.json");
const localConfigFile = join(securityDir, "monitor_config.local.json");
const latestFile = join(securityDir, "latest_breach_scan.json");

const HIBP_API_KEY = process.env.HIBP_API_KEY?.trim();
const HIBP_BASE = "https://haveibeenpwned.com/api/v3";
const XON_BASE = "https://api.xposedornot.com/v1";
const CAVALIER_BASE = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools";
const LEAKCHECK_BASE = "https://leakcheck.io";
const USER_AGENT = "darkweb-monitor-dashboard-breach-monitor";

// 보조 소스 — 키-게이트(있으면 사용, 없으면 조용히 skip). Hudson Rock OSINT 는 무료라 토글로만 제어.
const INTELX_API_KEY = process.env.INTELX_API_KEY?.trim();
const INTELX_HOST = process.env.INTELX_API_HOST?.trim() || "https://2.intelx.io";
const INTELX_BUCKETS = (process.env.INTELX_BUCKETS ?? "").split(",").map((s) => s.trim()).filter(Boolean);
const LEAKCHECK_API_KEY = process.env.LEAKCHECK_API_KEY?.trim();
const HUDSONROCK_OSINT = (process.env.HUDSONROCK_OSINT_ENABLED ?? "1") !== "0";
const GITHUB_TOKEN = process.env.GITHUB_TOKEN?.trim();
const GITHUB_API = "https://api.github.com";

// LeakCheck 노출 필드(카테고리) → 한글. 값 자체는 저장하지 않는다(분류만).
const LEAK_FIELD_KO = {
  password: "비밀번호", username: "사용자명", email: "이메일", phone: "전화번호",
  dob: "생년월일", ssn: "주민번호", address: "주소", zip: "우편번호", ip: "IP 주소",
  first_name: "이름", last_name: "이름", name: "이름",
};
function mapLeakFields(fields) {
  const out = [...new Set((fields ?? []).map((f) => LEAK_FIELD_KO[f]).filter(Boolean))];
  return out.length ? out : ["유출 기록"];
}

// HIBP/XposedOrNot 노출 항목(영문) → 한글 표시 매핑(미정의는 원문 유지).
const DATA_CLASS_KO = {
  "Email addresses": "이메일",
  Passwords: "비밀번호",
  Usernames: "사용자명",
  Names: "이름",
  "Phone numbers": "전화번호",
  "Physical addresses": "주소",
  "IP addresses": "IP 주소",
  "Dates of birth": "생년월일",
  Genders: "성별",
  "Credit cards": "신용카드",
  "Bank account numbers": "계좌번호",
  "Security questions and answers": "보안 질문/답변",
  "Auth tokens": "인증 토큰",
  "Geographic locations": "위치 정보",
  "Job titles": "직책",
  Employers: "직장",
  "Social media profiles": "소셜 프로필",
};

// 노출 항목 → 심각도. 최댓값을 채택한다.
const SEVERITY_RANK = { low: 0, medium: 1, high: 2, critical: 3 };
function severityForDataClasses(dataClasses) {
  let sev = "low";
  const bump = (s) => {
    if (SEVERITY_RANK[s] > SEVERITY_RANK[sev]) sev = s;
  };
  for (const dc of dataClasses) {
    if (["Passwords", "Credit cards", "Bank account numbers"].includes(dc)) bump("critical");
    else if (["Security questions and answers", "Auth tokens"].includes(dc)) bump("high");
    else if (["Phone numbers", "Physical addresses", "Dates of birth", "IP addresses"].includes(dc))
      bump("medium");
  }
  return sev;
}

function maskLocalPart(alias) {
  if (!alias) return "***";
  if (alias.length <= 2) return `${alias[0] ?? "*"}***`;
  return `${alias.slice(0, 2)}***`;
}

function findingId(domain, alias, breachName) {
  return createHash("sha1").update(`${domain}|${alias}|${breachName}`).digest("hex").slice(0, 12);
}

function isoToDate(iso) {
  if (!iso) return "";
  return String(iso).slice(0, 10); // YYYY-MM-DD
}

function todayStamp() {
  return new Date().toISOString().replace(/[:.]/g, "-");
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// 견고한 JSON fetch: 429/5xx 는 Retry-After/지수 백오프로 재시도. 실패해도 throw 안 함.
async function fetchJson(url, { headers = {}, method = "GET", body } = {}, { retries = 2, baseDelay = 800 } = {}) {
  for (let attempt = 0; attempt <= retries; attempt++) {
    try {
      const res = await fetch(url, { method, headers: { "user-agent": USER_AGENT, ...headers }, body });
      if ((res.status === 429 || res.status >= 500) && attempt < retries) {
        const ra = Number(res.headers.get("retry-after"));
        await sleep(ra ? ra * 1000 : baseDelay * (attempt + 1));
        continue;
      }
      let data = null;
      try { data = await res.json(); } catch { /* 비JSON/빈 본문 */ }
      return { ok: res.ok, status: res.status, data };
    } catch (err) {
      if (attempt < retries) { await sleep(baseDelay * (attempt + 1)); continue; }
      return { ok: false, status: 0, data: null, error: err };
    }
  }
  return { ok: false, status: 0, data: null };
}

async function ensureDirs() {
  await mkdir(securityDir, { recursive: true });
  await mkdir(historyDir, { recursive: true });
  await mkdir(join(root, "lib", "data", "generated"), { recursive: true });
}

async function readJson(path, fallback) {
  try {
    return JSON.parse(await readFile(path, "utf8"));
  } catch {
    return fallback;
  }
}

// base config + local override(.gitignore, 실제 이메일 보관) 병합.
async function loadConfig() {
  const base = await readJson(configFile, { domains: [], accounts: [], minSeverity: "low" });
  const local = await readJson(localConfigFile, null);
  if (!local) return base;
  return {
    ...base,
    ...local,
    domains: [...new Set([...(base.domains ?? []), ...(local.domains ?? [])])].filter(Boolean),
    accounts: [...new Set([...(base.accounts ?? []), ...(local.accounts ?? [])])].filter(Boolean),
  };
}

function koDataClasses(list) {
  return (list ?? []).map((dc) => DATA_CLASS_KO[dc] ?? dc);
}

// ── HIBP (유료키) ──────────────────────────────────────────────────────────
async function hibpFetch(path) {
  // 도메인 전수 검색 대비: 429(레이트리밋)는 Retry-After 만큼 대기 후 재시도.
  for (let attempt = 0; attempt < 4; attempt++) {
    const res = await fetch(`${HIBP_BASE}${path}`, {
      headers: { "hibp-api-key": HIBP_API_KEY, "user-agent": USER_AGENT },
    });
    if (res.status === 404 || res.status === 204) return null; // 유출 없음
    if (res.status === 429) {
      const ra = Number(res.headers.get("retry-after")) || 2 * (attempt + 1);
      console.warn(`[monitor] HIBP 429 — ${ra}s 대기 후 재시도 (${attempt + 1}/4)`);
      await sleep(ra * 1000);
      continue;
    }
    if (!res.ok) throw new Error(`HIBP ${path} → HTTP ${res.status} ${(await res.text()).slice(0, 200)}`);
    return res.json();
  }
  throw new Error(`HIBP ${path} → 429 반복(레이트리밋) — 재시도 한도 초과`);
}

async function loadHibpCatalog() {
  try {
    const res = await fetch(`${HIBP_BASE}/breaches`, { headers: { "user-agent": USER_AGENT } });
    if (!res.ok) return new Map();
    const arr = await res.json();
    const map = new Map();
    for (const b of arr) {
      map.set(b.Name, {
        title: b.Title ?? b.Name,
        date: isoToDate(b.BreachDate),
        dataClasses: Array.isArray(b.DataClasses) ? b.DataClasses : [],
      });
    }
    return map;
  } catch {
    return new Map();
  }
}

function buildFindingsFromDomainMap(domain, aliasMap, catalog, nowIso) {
  const findings = [];
  for (const [alias, breachNames] of Object.entries(aliasMap || {})) {
    for (const breachName of breachNames) {
      const meta = catalog.get(breachName) || { title: breachName, date: "", dataClasses: [] };
      findings.push(makeFinding(domain, alias, breachName, meta, nowIso));
    }
  }
  return findings;
}

// ── XposedOrNot (무료, 키 불필요, 실데이터) ────────────────────────────────
// 카탈로그: breachID → { title, date, dataClasses }
async function loadXonCatalog() {
  try {
    const res = await fetch(`${XON_BASE}/breaches`, { headers: { "user-agent": USER_AGENT } });
    if (!res.ok) return new Map();
    const body = await res.json();
    const arr = Array.isArray(body) ? body : body.exposedBreaches ?? [];
    const map = new Map();
    for (const b of arr) {
      map.set(b.breachID, {
        title: b.breachID,
        date: isoToDate(b.breachedDate),
        dataClasses: Array.isArray(b.exposedData) ? b.exposedData : [],
      });
    }
    return map;
  } catch {
    return new Map();
  }
}

// 계정 1건의 유출 사건명 배열 조회. 유출 없음/오류면 [].
async function xonCheckEmail(email) {
  try {
    const res = await fetch(`${XON_BASE}/check-email/${encodeURIComponent(email)}`, {
      headers: { "user-agent": USER_AGENT },
    });
    if (!res.ok) return [];
    const body = await res.json();
    if (body?.Error) return []; // {"Error":"Not found"}
    // 응답: { breaches: [[name1, name2, ...]] }
    const nested = body?.breaches;
    if (Array.isArray(nested) && Array.isArray(nested[0])) return nested[0].filter(Boolean);
    if (Array.isArray(nested)) return nested.filter((x) => typeof x === "string");
    return [];
  } catch {
    return [];
  }
}

async function collectXposedOrNot(accounts, catalog, nowIso) {
  const findings = [];
  for (const acct of accounts) {
    const email = String(acct).trim().toLowerCase();
    const [alias, domain] = email.split("@");
    if (!alias || !domain) continue;
    const names = await xonCheckEmail(email);
    for (const breachName of names) {
      const meta = catalog.get(breachName) || { title: breachName, date: "", dataClasses: [] };
      findings.push(makeFinding(domain, alias, breachName, meta, nowIso));
    }
    await sleep(350); // 무료 API 레이트리밋 배려
  }
  return findings;
}

function makeFinding(domain, alias, breachName, meta, nowIso) {
  return {
    id: findingId(domain, alias, breachName),
    accountMasked: `${maskLocalPart(alias)}@${domain}`,
    domain,
    breachName,
    breachTitle: meta.title || breachName,
    breachDate: meta.date || "",
    dataClasses: koDataClasses(meta.dataClasses),
    severity: severityForDataClasses(meta.dataClasses ?? []),
    isNew: false,
    discoveredAt: nowIso,
    source: "",
  };
}

// 카탈로그 없이 보조 소스(Hudson Rock 계정별·IntelX·LeakCheck)가 직접 finding 을 만들 때 사용.
// dataClasses 는 이미 한글 분류, severity 도 직접 지정. idSeed 로 finding_id 충돌 방지(소스별 레코드).
function makeRawFinding({ domain, alias, breachName, breachTitle, breachDate, dataClassesKo, severity, source, referenceUrl }, nowIso, idSeed = "") {
  const aliasKey = alias || "*";
  return {
    id: findingId(domain, aliasKey, idSeed ? `${breachName}|${idSeed}` : breachName),
    accountMasked: aliasKey === "*" ? `*@${domain}` : `${maskLocalPart(aliasKey)}@${domain}`,
    domain,
    breachName,
    breachTitle: breachTitle || breachName,
    breachDate: breachDate || "",
    dataClasses: dataClassesKo,
    severity,
    isNew: false,
    discoveredAt: nowIso,
    source,
    referenceUrl: referenceUrl || "",
  };
}

// ── Hudson Rock Cavalier (무료, 키 불필요) — 도메인 전수 인포스틸러 감염 ──────
async function collectCavalier(domains, nowIso) {
  const out = [];
  for (const domain of domains) {
    try {
      const res = await fetch(`${CAVALIER_BASE}/search-by-domain?domain=${encodeURIComponent(domain)}`, {
        headers: { "user-agent": USER_AGENT },
      });
      if (!res.ok) continue;
      const d = await res.json();
      const urls = (d?.data?.all_urls ?? [])
        .slice(0, 30)
        .map((u) => ({ url: u.url, type: u.type, occurrence: u.occurrence }));
      out.push({
        domain,
        source: "Hudson Rock Cavalier",
        total: d.total ?? 0,
        employees: d.employees ?? 0,
        users: d.users ?? 0,
        thirdParties: d.third_parties ?? 0,
        affectedUrls: urls,
        scannedAt: nowIso,
      });
      await sleep(300);
    } catch {
      // 도메인별 실패는 건너뜀
    }
  }
  return out;
}

// ── Hudson Rock 계정별 인포스틸러 (무료) → breach_findings ───────────────────
// search-by-email 로 모니터링 계정의 인포스틸러 감염을 조회. 민감값(top_passwords·ip·PC명)은
// 절대 저장하지 않고, 마스킹 계정 + 분류(비밀번호/자격증명/감염) + 카운트만 남긴다.
async function collectCavalierAccounts(accounts, nowIso) {
  const findings = [];
  const hosts = []; // 감염 호스트(피해자) 상세 — 마스킹 값만
  for (const acct of accounts) {
    const email = String(acct).trim().toLowerCase();
    const [alias, domain] = email.split("@");
    if (!alias || !domain) continue;
    const r = await fetchJson(`${CAVALIER_BASE}/search-by-email?email=${encodeURIComponent(email)}`);
    const stealers = Array.isArray(r.data?.stealers) ? r.data.stealers : [];
    if (stealers.length) {
      const accountMasked = `${maskLocalPart(alias)}@${domain}`;
      const seen = new Set();
      let corp = 0, hasPw = false, hasLogin = false, last = "";
      const families = new Set();
      for (const s of stealers) {
        const key = `${s.computer_name}|${s.date_compromised}|${s.ip}`; // 동일 로그 중복 제거
        if (seen.has(key)) continue;
        seen.add(key);
        corp += Number(s.total_corporate_services || 0);
        if (Array.isArray(s.top_passwords) && s.top_passwords.length) hasPw = true;
        if (Array.isArray(s.top_logins) && s.top_logins.length) hasLogin = true;
        if (s.stealer_family) families.add(s.stealer_family);
        const d = String(s.date_compromised || "").slice(0, 10);
        if (d > last) last = d;
        // 호스트 상세(피해 PC 단위). top_passwords/ip 는 Hudson Rock 이 부분 마스킹한 값만.
        hosts.push({
          hostId: findingId(accountMasked, String(s.computer_name || ""), `${s.date_compromised || ""}|${s.ip || ""}`),
          accountMasked, domain,
          computerName: s.computer_name || null,
          operatingSystem: s.operating_system || null,
          ip: s.ip || null,
          dateCompromised: d || null,
          stealerFamily: s.stealer_family || null,
          malwarePath: s.malware_path || null,
          antiviruses: Array.isArray(s.antiviruses) ? s.antiviruses : [],
          totalCorporateServices: Number(s.total_corporate_services || 0),
          totalUserServices: Number(s.total_user_services || 0),
          topPasswords: Array.isArray(s.top_passwords) ? s.top_passwords.slice(0, 12) : [],
          topLogins: Array.isArray(s.top_logins) ? s.top_logins.slice(0, 12) : [],
          scannedAt: nowIso,
        });
      }
      const dataClasses = [];
      if (hasLogin) dataClasses.push("자격증명");
      if (hasPw) dataClasses.push("비밀번호");
      dataClasses.push("인포스틸러 감염");
      findings.push(makeRawFinding({
        domain, alias,
        breachName: families.size ? `Infostealer (${[...families].join(", ")})` : "Infostealer",
        breachTitle: `인포스틸러 감염 (${seen.size}대 기기)`,
        breachDate: last,
        dataClassesKo: dataClasses,
        severity: corp > 0 ? "high" : "medium", // 사내 서비스 자격증명 탈취면 high
        source: "Hudson Rock Cavalier (계정별)",
      }, nowIso));
    }
    await sleep(1000); // 무료 OSINT 공정사용 — ~1 req/s
  }
  return { findings, hosts };
}

// ── Intelligence X (키-게이트) → breach_findings ────────────────────────────
// 도메인 전수 유출 레코드. async: 인증확인 → search(term=domain) → result 폴링.
async function collectIntelx(domains, nowIso) {
  if (!INTELX_API_KEY) return { findings: [], used: false, count: 0 };
  const headers = { "x-key": INTELX_API_KEY, "content-type": "application/json" };
  const info = await fetchJson(`${INTELX_HOST}/authenticate/info`, { headers });
  if (!info.ok) {
    console.warn(`[intelx] 인증/크레딧 확인 실패 HTTP ${info.status} — 건너뜀`);
    return { findings: [], used: false, count: 0 };
  }
  const findings = [];
  for (const domain of domains) {
    const start = await fetchJson(`${INTELX_HOST}/intelligent/search`, {
      method: "POST", headers,
      body: JSON.stringify({
        term: domain, maxresults: 100, media: 0, sort: 4, timeout: 5,
        ...(INTELX_BUCKETS.length ? { buckets: INTELX_BUCKETS } : {}),
      }),
    });
    const id = start.data?.id;
    if (!id || start.data?.status === 2) continue; // 무효 term/쿼터 없음
    const records = [];
    for (let i = 0; i < 8; i++) {
      const r = await fetchJson(`${INTELX_HOST}/intelligent/search/result?id=${encodeURIComponent(id)}&limit=100`, { headers });
      if (Array.isArray(r.data?.records)) records.push(...r.data.records);
      const st = r.data?.status;
      if (st === 1 || st === 2) break; // 1=완료, 2=id 없음
      await sleep(1200); // 3=준비중 → 백오프 폴링
    }
    const seen = new Set();
    for (const rec of records) {
      if (seen.has(rec.systemid)) continue;
      seen.add(rec.systemid);
      const bucket = String(rec.bucket || "");
      const name = String(rec.name || bucket || "IntelX record");
      const severity = /private|credential|combo|dump/i.test(`${bucket} ${name}`)
        ? "high" : /leak|public/i.test(bucket) ? "medium" : "low";
      const dataClasses = /combo|dump|cred/i.test(name)
        ? ["이메일", "비밀번호"] : /paste/i.test(bucket) ? ["페이스트"] : ["유출 기록"];
      findings.push(makeRawFinding({
        domain, alias: "*",
        breachName: name.slice(0, 80),
        breachTitle: name.slice(0, 120),
        breachDate: String(rec.date || "").slice(0, 10),
        dataClassesKo: dataClasses, severity,
        source: "Intelligence X",
      }, nowIso, rec.systemid));
    }
  }
  return { findings, used: true, count: findings.length };
}

// ── LeakCheck → breach_findings ─────────────────────────────────────────────
// 키 있으면 v2 type=domain(도메인 전수, 평문 password 는 절대 저장 안 함),
// 없으면 무료 public(?check=) 으로 계정별(roster) 조회. 둘 다 마스킹만 저장.
async function collectLeakcheck(domains, accounts, nowIso) {
  if (LEAKCHECK_API_KEY) {
    const findings = [];
    for (const domain of domains) {
      let offset = 0;
      for (let page = 0; page < 10; page++) {
        const r = await fetchJson(
          `${LEAKCHECK_BASE}/api/v2/query/${encodeURIComponent(domain)}?type=domain&limit=100&offset=${offset}`,
          { headers: { "X-API-Key": LEAKCHECK_API_KEY } },
        );
        if (!r.ok) { if (page === 0) console.warn(`[leakcheck] v2 HTTP ${r.status} — 건너뜀`); break; }
        const result = Array.isArray(r.data?.result) ? r.data.result : [];
        for (const e of result) {
          const email = String(e.email || "").toLowerCase();
          const [alias, dm] = email.includes("@") ? email.split("@") : ["*", domain];
          const fields = Array.isArray(e.fields) ? e.fields : [];
          const sev = fields.includes("password") || fields.includes("ssn")
            ? "high" : fields.includes("dob") || fields.includes("address") ? "medium" : "low";
          // password 등 평문은 매핑에서 제외 — fields(분류)만 사용.
          findings.push(makeRawFinding({
            domain: dm || domain, alias: alias || "*",
            breachName: e.source?.name || "LeakCheck",
            breachTitle: e.source?.name || "LeakCheck",
            breachDate: String(e.source?.breach_date || "").slice(0, 10),
            dataClassesKo: mapLeakFields(fields), severity: sev,
            source: "LeakCheck",
          }, nowIso, email || undefined));
        }
        if (result.length < 100) break;
        offset += 100;
        await sleep(400);
      }
    }
    return { findings, used: true, count: findings.length, mode: "v2-domain" };
  }
  if (accounts.length) {
    // 무료 public — 도메인 검색 미지원 → 계정별. 응답에 평문 없음(설계상 안전).
    const findings = [];
    for (const acct of accounts) {
      const email = String(acct).trim().toLowerCase();
      const [alias, domain] = email.split("@");
      if (!alias || !domain) continue;
      const r = await fetchJson(`${LEAKCHECK_BASE}/api/public?check=${encodeURIComponent(email)}`);
      const sources = Array.isArray(r.data?.sources) ? r.data.sources : [];
      const fields = Array.isArray(r.data?.fields) ? r.data.fields : [];
      const dataClasses = mapLeakFields(fields);
      const sev = fields.includes("password") || fields.includes("ssn") ? "high" : "low";
      for (const src of sources) {
        findings.push(makeRawFinding({
          domain, alias,
          breachName: src.name || "LeakCheck",
          breachTitle: src.name || "LeakCheck",
          breachDate: String(src.date || ""),
          dataClassesKo: dataClasses, severity: sev,
          source: "LeakCheck (public)",
        }, nowIso, src.name));
      }
      await sleep(1100); // 무료 ~1 req/s
    }
    return { findings, used: true, count: findings.length, mode: "public" };
  }
  return { findings: [], used: false, count: 0, mode: "" };
}

// ── GitHub 공개 노출 검색 (키-게이트) → breach_findings ──────────────────────
// 공개 GitHub 코드에서 도메인+자격증명 키워드 검색. 자격증명 값은 저장하지 않고
// repo/파일/URL 포인터만 남긴다(관리자 수동 검토용).
async function collectGithub(domains, nowIso) {
  if (!GITHUB_TOKEN) return { findings: [], used: false, count: 0 };
  const headers = {
    Authorization: `Bearer ${GITHUB_TOKEN}`,
    Accept: "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
  };
  const findings = [];
  const seen = new Set();
  for (const domain of domains) {
    const q = encodeURIComponent(`"@${domain}" password`); // 이메일형(@도메인)으로 노이즈 축소
    const r = await fetchJson(`${GITHUB_API}/search/code?q=${q}&per_page=20`, { headers }, { retries: 1, baseDelay: 2000 });
    const items = Array.isArray(r.data?.items) ? r.data.items : [];
    for (const it of items) {
      const repo = it.repository?.full_name || "";
      const path = it.path || "";
      const url = it.html_url || "";
      const key = `${repo}/${path}`;
      if (!repo || seen.has(key)) continue;
      seen.add(key);
      findings.push(makeRawFinding({
        domain, alias: "*",
        breachName: "GitHub 공개 노출",
        breachTitle: `${repo} · ${path}`.slice(0, 120),
        dataClassesKo: ["공개 코드 노출", "자격증명 의심"],
        severity: "high",
        source: "공개 노출 (GitHub)",
        referenceUrl: url,
      }, nowIso, key));
    }
    await sleep(1500); // 코드 검색 레이트리밋 배려
  }
  return { findings, used: true, count: findings.length };
}

// ── ProxyNova COMB 콤보리스트 검색 (무료 키리스, 합법 공개) ──────────────────
// 다크웹 유통 콤보리스트에서 도메인 단위 노출 계정 열거(명부 불필요). 평문 비번 미저장(분류만).
// API 가 substring 퍼지매칭이라 email 이 정확히 @domain 으로 끝나는지 가드 필수.
// 날짜 정규화: "2019-01"/"2019" 도 유효 날짜(YYYY-MM-DD)로, 아니면 null
function normBreachDate(d) {
  const s = String(d ?? "").trim();
  if (/^\d{4}-\d{2}-\d{2}/.test(s)) return s.slice(0, 10);
  if (/^\d{4}-\d{2}$/.test(s)) return `${s}-01`;
  if (/^\d{4}$/.test(s)) return `${s}-01-01`;
  return null;
}

async function collectProxynovaComb(domains, nowIso) {
  const findings = [];
  const emails = new Set(); // 노출 계정 — LeakCheck 유출이력 보강용
  for (const domain of domains) {
    const suffix = `@${domain.toLowerCase()}`;
    const seen = new Set();
    for (let start = 0; start < 300; start += 100) {
      const r = await fetchJson(`https://api.proxynova.com/comb?query=${encodeURIComponent(suffix)}&start=${start}&limit=100`, {}, { retries: 1, baseDelay: 1000 });
      const lines = Array.isArray(r.data?.lines) ? r.data.lines : [];
      if (!lines.length) break;
      for (const line of lines) {
        const i = line.indexOf(":"); // 우측(평문 비번) 폐기
        const email = (i === -1 ? line : line.slice(0, i)).trim().toLowerCase();
        if (!email.endsWith(suffix)) continue; // 정확매칭 가드
        const alias = email.slice(0, email.length - suffix.length);
        if (!alias || seen.has(email)) continue;
        seen.add(email);
        emails.add(email);
        findings.push(makeRawFinding({
          domain, alias,
          breachName: "COMB 통합본 (다크웹 유통)",
          breachTitle: "COMB — 2021년 약 32억건 email:password 유출 통합본(다크웹·해킹포럼 유통)",
          breachDate: "2021-02-01", // COMB 통합본 등장 시점. 개별 계정 유출시점이 아님.
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
  // 유출이력 보강 — 각 노출 계정이 "언제·어디서" 떴는지. 평문 미수집(소스명·날짜·필드만).
  // LeakCheck + XposedOrNot 두 카탈로그로 커버리지 극대화. (이메일 원문 외부 조회는 운영자 승인)
  const xonCatalog = await loadXonCatalog();
  for (const email of emails) {
    const at = email.indexOf("@");
    const alias = email.slice(0, at), dm = email.slice(at + 1);
    // (a) LeakCheck 공개
    const lc = await fetchJson(`${LEAKCHECK_BASE}/api/public?check=${encodeURIComponent(email)}`, {}, { retries: 1, baseDelay: 800 });
    const sources = Array.isArray(lc.data?.sources) ? lc.data.sources : [];
    const fields = Array.isArray(lc.data?.fields) ? lc.data.fields : [];
    for (const s of sources) {
      const name = String(s?.name ?? "").trim() || "미상 유출 출처";
      findings.push(makeRawFinding({
        domain: dm, alias,
        breachName: name,
        breachTitle: `${name} 유출 이력`,
        breachDate: normBreachDate(s?.date) ?? undefined,
        dataClassesKo: mapLeakFields(fields),
        severity: fields.includes("password") ? "high" : "medium",
        source: "유출이력 (LeakCheck)",
      }, nowIso, `lc|${name}`));
    }
    // (b) XposedOrNot — 다른 카탈로그라 LeakCheck 미커버 계정의 사건·날짜를 추가 확보
    const xnames = await xonCheckEmail(email);
    for (const name of xnames) {
      const meta = xonCatalog.get(name);
      const dc = meta?.dataClasses ?? [];
      findings.push(makeRawFinding({
        domain: dm, alias,
        breachName: name,
        breachTitle: meta?.title ? `${meta.title} 유출 이력` : `${name} 유출 이력`,
        breachDate: normBreachDate(meta?.date) ?? undefined,
        dataClassesKo: dc.length ? koDataClasses(dc) : ["유출 기록"],
        severity: dc.length ? severityForDataClasses(dc) : "medium",
        source: "유출이력 (XposedOrNot)",
      }, nowIso, `xon|${name}`));
    }
    await sleep(350);
  }
  return { findings, used: true, count: findings.length, emails: [...emails] };
}

function summarize(findings, domains) {
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 };
  const byDomainMap = new Map(domains.map((d) => [d, 0]));
  let newCount = 0;
  for (const f of findings) {
    bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
    byDomainMap.set(f.domain, (byDomainMap.get(f.domain) ?? 0) + 1);
    if (f.isNew) newCount++;
  }
  return {
    total: findings.length,
    newCount,
    bySeverity,
    byDomain: [...byDomainMap.entries()].map(([domain, count]) => ({ domain, count })),
  };
}

function sortFindings(findings) {
  return findings.sort((a, b) => {
    if (a.isNew !== b.isNew) return a.isNew ? -1 : 1;
    if (SEVERITY_RANK[b.severity] !== SEVERITY_RANK[a.severity])
      return SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
    return (b.breachDate || "").localeCompare(a.breachDate || "");
  });
}

async function writeGenerated(scan) {
  const banner = "// Auto-generated by scripts/monitor_breaches.mjs. Do not edit by hand.\n";
  const body =
    banner +
    'import type { BreachScan } from "@/lib/types/breachMonitor";\n\n' +
    "export const breachScan: BreachScan = " +
    JSON.stringify(scan, null, 2) +
    ";\n";
  await writeFile(generatedFile, body, "utf8");
}

// 최선노력 Supabase 적재(미설정 시 조용히 건너뜀, 실패해도 배치 중단 안 함).
async function loadSupabase(scan) {
  const url = process.env.SUPABASE_URL?.trim();
  const key = process.env.SUPABASE_SERVICE_ROLE_KEY?.trim();
  if (!url || !key || scan.isDemo) return;
  try {
    const sbHeaders = {
      apikey: key,
      Authorization: `Bearer ${key}`,
      "Content-Type": "application/json",
      Prefer: "resolution=merge-duplicates,return=minimal",
    };
    const rows = scan.findings.map((f) => ({
      finding_id: f.id,
      account_masked: f.accountMasked,
      domain: f.domain,
      breach_name: f.breachName,
      breach_title: f.breachTitle,
      breach_date: f.breachDate || null,
      data_classes: f.dataClasses,
      severity: f.severity,
      is_new: f.isNew,
      discovered_at: f.discoveredAt,
      source: f.source,
      reference_url: f.referenceUrl || null,
    }));
    if (rows.length) {
      const res = await fetch(`${url}/rest/v1/breach_findings?on_conflict=finding_id`, {
        method: "POST", headers: sbHeaders, body: JSON.stringify(rows),
      });
      if (res.ok) console.log(`[supabase] breach_findings upsert ${rows.length}행`);
      else console.warn(`[supabase] breach_findings 적재 실패 HTTP ${res.status} (002 마이그레이션 확인)`);
    }
    // 인포스틸러(도메인 전수) 적재
    const infRows = (scan.infostealer ?? []).map((i) => ({
      domain: i.domain,
      source: i.source,
      total: i.total,
      employees: i.employees,
      users: i.users,
      third_parties: i.thirdParties,
      affected_urls: i.affectedUrls,
      scanned_at: i.scannedAt,
    }));
    if (infRows.length) {
      const res2 = await fetch(`${url}/rest/v1/infostealer_findings?on_conflict=domain`, {
        method: "POST", headers: sbHeaders, body: JSON.stringify(infRows),
      });
      if (res2.ok) console.log(`[supabase] infostealer_findings upsert ${infRows.length}행`);
      else console.warn(`[supabase] infostealer 적재 실패 HTTP ${res2.status} (004 마이그레이션 확인)`);
    }
    // 감염 호스트 상세 적재 (006)
    const hostRows = (scan.infostealerHosts ?? []).map((h) => ({
      host_id: h.hostId, account_masked: h.accountMasked, domain: h.domain,
      computer_name: h.computerName, operating_system: h.operatingSystem, ip: h.ip,
      date_compromised: h.dateCompromised, stealer_family: h.stealerFamily, malware_path: h.malwarePath,
      antiviruses: h.antiviruses, total_corporate_services: h.totalCorporateServices,
      total_user_services: h.totalUserServices, top_passwords: h.topPasswords, top_logins: h.topLogins,
      scanned_at: h.scannedAt,
    }));
    if (hostRows.length) {
      const res3 = await fetch(`${url}/rest/v1/infostealer_hosts?on_conflict=host_id`, {
        method: "POST", headers: sbHeaders, body: JSON.stringify(hostRows),
      });
      if (res3.ok) console.log(`[supabase] infostealer_hosts upsert ${hostRows.length}행`);
      else console.warn(`[supabase] infostealer_hosts 적재 실패 HTTP ${res3.status} (006 마이그레이션 확인)`);
    }
  } catch (err) {
    console.warn(`[supabase] 적재 건너뜀: ${err.message}`);
  }
}

async function main() {
  await ensureDirs();
  const nowIso = new Date().toISOString();
  const config = await loadConfig();
  const domains = Array.isArray(config.domains) ? config.domains.filter(Boolean) : [];
  const accounts = Array.isArray(config.accounts) ? config.accounts.filter(Boolean) : [];

  const previous = await readJson(latestFile, null);
  const prevIds = new Set((previous?.findings ?? []).map((f) => f.id));
  const prevHistory = Array.isArray(previous?.history) ? previous.history : [];

  let findings = [];
  let status = "ok";
  let isDemo = false;
  let source;
  let note;

  if (HIBP_API_KEY) {
    // (1) HIBP 도메인 전수 검색
    source = "Have I Been Pwned (도메인 검색 API)";
    try {
      const catalog = await loadHibpCatalog();
      for (const domain of domains) {
        console.log(`[monitor] HIBP 도메인 검색: ${domain}`);
        const aliasMap = await hibpFetch(`/breacheddomain/${encodeURIComponent(domain)}`);
        findings.push(...buildFindingsFromDomainMap(domain, aliasMap, catalog, nowIso));
      }
      for (const acct of accounts) {
        const [alias, domain] = String(acct).split("@");
        if (!alias || !domain) continue;
        const breaches = await hibpFetch(`/breachedaccount/${encodeURIComponent(acct)}?truncateResponse=true`);
        const names = (breaches ?? []).map((b) => b.Name);
        findings.push(...buildFindingsFromDomainMap(domain, { [alias]: names }, catalog, nowIso));
      }
      console.log(`[monitor] 유출 항목 ${findings.length}건 발견`);
    } catch (err) {
      status = "error";
      note = `HIBP 조회 실패: ${err.message}`;
      console.error(`[monitor] ${note}`);
      if (previous?.findings?.length) {
        findings = previous.findings.map((f) => ({ ...f, isNew: false }));
        source = previous.source;
      }
    }
  } else if (accounts.length) {
    // (2) 무료 XposedOrNot 계정별 조회(실데이터)
    source = "XposedOrNot (계정별 유출 조회, 무료)";
    try {
      const catalog = await loadXonCatalog();
      console.log(`[monitor] XposedOrNot 계정 ${accounts.length}건 조회`);
      findings = await collectXposedOrNot(accounts, catalog, nowIso);
      console.log(`[monitor] 유출 항목 ${findings.length}건 발견`);
    } catch (err) {
      status = "error";
      note = `XposedOrNot 조회 실패: ${err.message}`;
      console.error(`[monitor] ${note}`);
      if (previous?.findings?.length) {
        findings = previous.findings.map((f) => ({ ...f, isNew: false }));
        source = previous.source;
      }
    }
  } else {
    // (3) 소스 미설정 — 가짜(데모) 데이터를 만들지 않는다. 대시보드는 Supabase 실데이터만 표시.
    status = "no_source";
    source = "(모니터링 대상 미설정)";
    note =
      "HIBP_API_KEY 또는 모니터링 대상 계정(accounts)이 설정되지 않았습니다. " +
      "data/security/monitor_config.local.json 의 accounts 에 회사 계정 이메일을 넣으면(무료 XposedOrNot) 실데이터를 수집합니다.";
    console.log("[monitor] 소스 미설정 → 수집 건너뜀");
  }

  // 1차(주) 소스 결과에 출처 라벨 부여 + 건수 기록
  for (const f of findings) f.source = f.source || source;
  const primaryCount = findings.length;

  // ── 보조 소스 (실데이터 한정) — 키 있으면/무료면 추가 수집 후 병합 ──────────
  const provenanceExtra = [];
  let infostealerHosts = []; // 감염 호스트 상세
  if (!isDemo) {
    // IntelX (도메인 전수, 키-게이트)
    if (INTELX_API_KEY && domains.length) {
      console.log(`[monitor] IntelX 도메인 검색 ${domains.length}건`);
      const ix = await collectIntelx(domains, nowIso);
      if (ix.used) {
        findings.push(...ix.findings);
        provenanceExtra.push({ name: "Intelligence X", kind: "breach", endpoint: "2.intelx.io /intelligent/search", count: ix.count, scannedAt: nowIso });
      }
    }
    // LeakCheck (키 있으면 도메인 v2, 없으면 무료 public 계정별)
    if (LEAKCHECK_API_KEY ? domains.length : accounts.length) {
      console.log(`[monitor] LeakCheck 조회 (${LEAKCHECK_API_KEY ? "v2 도메인" : "public 계정별"})`);
      const lc = await collectLeakcheck(domains, accounts, nowIso);
      if (lc.used) {
        findings.push(...lc.findings);
        provenanceExtra.push({
          name: lc.mode === "v2-domain" ? "LeakCheck" : "LeakCheck (public)",
          kind: "breach",
          endpoint: lc.mode === "v2-domain" ? "leakcheck.io /api/v2/query?type=domain" : "leakcheck.io /api/public",
          count: lc.count, scannedAt: nowIso,
        });
      }
    }
    // Hudson Rock 계정별 인포스틸러 (무료) → breach_findings + 호스트 상세
    if (HUDSONROCK_OSINT && accounts.length) {
      console.log(`[monitor] Hudson Rock 계정별 인포스틸러 ${accounts.length}건`);
      const hr = await collectCavalierAccounts(accounts, nowIso);
      infostealerHosts = hr.hosts;
      if (hr.findings.length) {
        findings.push(...hr.findings);
        provenanceExtra.push({ name: "Hudson Rock Cavalier (계정별)", kind: "breach", endpoint: "cavalier.hudsonrock.com /search-by-email", count: hr.findings.length, scannedAt: nowIso });
      }
    }
    // GitHub 공개 노출 (키-게이트, 무료 합법 크롤링) → breach_findings
    if (GITHUB_TOKEN && domains.length) {
      console.log(`[monitor] GitHub 공개 노출 검색 ${domains.length}개 도메인`);
      const gh = await collectGithub(domains, nowIso);
      if (gh.used) {
        findings.push(...gh.findings);
        provenanceExtra.push({ name: "공개 노출 (GitHub)", kind: "breach", endpoint: "api.github.com /search/code", count: gh.count, scannedAt: nowIso });
      }
    }
    // ProxyNova COMB 콤보리스트 (무료 키리스) → 도메인 단위 노출 계정 열거
    if (domains.length) {
      console.log(`[monitor] ProxyNova COMB 콤보리스트 검색 ${domains.length}개 도메인`);
      const cb = await collectProxynovaComb(domains, nowIso);
      if (cb.used) {
        findings.push(...cb.findings);
        provenanceExtra.push({ name: "콤보리스트 (ProxyNova COMB)", kind: "breach", endpoint: "api.proxynova.com /comb", count: cb.count, scannedAt: nowIso });
        // 인포스틸러 교차매핑: COMB 발견 계정도 Hudson Rock search-by-email 으로 조회
        if (HUDSONROCK_OSINT && cb.emails.length) {
          console.log(`[monitor] Hudson Rock COMB 계정 교차 ${cb.emails.length}건`);
          const hx = await collectCavalierAccounts(cb.emails, nowIso);
          if (hx.findings.length) {
            findings.push(...hx.findings);
            provenanceExtra.push({ name: "Hudson Rock Cavalier (COMB 계정 교차)", kind: "breach", endpoint: "cavalier.hudsonrock.com /search-by-email", count: hx.findings.length, scannedAt: nowIso });
          }
          infostealerHosts = [...infostealerHosts, ...hx.hosts];
        }
      }
    }
  }

  // 중복 제거 (같은 finding_id 는 먼저 본 것 유지) + 신규 표시 + 정렬
  const byId = new Map();
  for (const f of findings) if (!byId.has(f.id)) byId.set(f.id, f);
  findings = [...byId.values()];
  for (const f of findings) f.isNew = !isDemo && !prevIds.has(f.id);
  findings = sortFindings(findings);

  // 다크웹 인포스틸러 감염 — 도메인 전수 (Hudson Rock Cavalier, 무료)
  let infostealer = [];
  if (!isDemo && domains.length) {
    console.log(`[monitor] Cavalier 도메인 전수 조회 ${domains.length}건`);
    infostealer = await collectCavalier(domains, nowIso);
    const totInf = infostealer.reduce((s, i) => s + i.total, 0);
    console.log(`[monitor] 인포스틸러 감염 합계 ${totInf}건`);
  }

  // 수집 출처 기록 (provenance)
  const sources = [
    {
      name: source,
      kind: "breach",
      endpoint: HIBP_API_KEY ? "haveibeenpwned.com /api/v3/breacheddomain" : (accounts.length ? "api.xposedornot.com /v1/check-email" : "demo"),
      count: primaryCount,
      scannedAt: nowIso,
    },
    ...provenanceExtra,
  ];
  if (infostealer.length) {
    sources.push({
      name: "Hudson Rock Cavalier",
      kind: "infostealer",
      endpoint: "cavalier.hudsonrock.com /search-by-domain",
      count: infostealer.reduce((s, i) => s + i.total, 0),
      scannedAt: nowIso,
    });
  }

  const summary = summarize(findings, domains);
  const history = [
    ...prevHistory.slice(-29),
    { scannedAt: nowIso, total: summary.total, newCount: summary.newCount },
  ];

  const scan = { generatedAt: nowIso, source, status, isDemo, domains, findings, summary, history, note, infostealer, infostealerHosts, sources };

  await writeFile(latestFile, JSON.stringify(scan, null, 2), "utf8");
  await writeFile(join(historyDir, `breach_scan_${todayStamp()}.json`), JSON.stringify(scan, null, 2), "utf8");
  await writeGenerated(scan);
  await loadSupabase(scan);

  console.log(
    `[monitor] 완료 — 총 ${summary.total}건 (신규 ${summary.newCount}, ` +
      `critical ${summary.bySeverity.critical}, high ${summary.bySeverity.high})`
  );
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});

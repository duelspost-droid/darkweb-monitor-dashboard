// 다크웹/유출 계정 모니터링 수집기 (로컬/CI 실행용).
//
// 데이터 소스 우선순위:
//  1) HIBP_API_KEY 가 있으면 Have I Been Pwned 도메인 검색 API(유료, 도메인 소유검증 필요)로
//     config.domains 의 도메인 계정 유출을 전수 조회한다.
//  2) 키가 없고 config.accounts(개별 이메일)가 있으면 무료 XposedOrNot API 로
//     계정별 유출을 조회한다(키 불필요, 실데이터).
//  3) 둘 다 없으면 페이지가 비지 않도록 데모 데이터(isDemo=true)를 생성한다.
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
const USER_AGENT = "darkweb-monitor-dashboard-breach-monitor";

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
  const res = await fetch(`${HIBP_BASE}${path}`, {
    headers: { "hibp-api-key": HIBP_API_KEY, "user-agent": USER_AGENT },
  });
  if (res.status === 404) return null; // 유출 없음
  if (res.status === 204) return null;
  if (!res.ok) throw new Error(`HIBP ${path} → HTTP ${res.status} ${(await res.text()).slice(0, 200)}`);
  return res.json();
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
        .slice(0, 10)
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

// ── 데모 데이터(소스 미설정 시) ────────────────────────────────────────────
function buildDemoFindings(domains, nowIso) {
  const demoBreaches = [
    { name: "LinkedIn", title: "LinkedIn", date: "2012-05-05", dataClasses: ["Email addresses", "Passwords"] },
    { name: "Collection1", title: "Collection #1", date: "2019-01-07", dataClasses: ["Email addresses", "Passwords"] },
    { name: "Dropbox", title: "Dropbox", date: "2012-07-01", dataClasses: ["Email addresses", "Passwords"] },
    { name: "Canva", title: "Canva", date: "2019-05-24", dataClasses: ["Email addresses", "Names", "Usernames", "Geographic locations"] },
    { name: "RiverCityMedia", title: "River City Media Spam List", date: "2017-01-01", dataClasses: ["Email addresses", "IP addresses", "Names", "Physical addresses"] },
  ];
  const demoAliases = ["admin", "finance.team", "hr", "support", "j.kim", "s.park"];
  const findings = [];
  const domain = domains[0] || "example.com";
  demoAliases.forEach((alias, i) => {
    const picks = demoBreaches.slice(i % 3, (i % 3) + 1 + (i % 2));
    for (const b of picks) findings.push(makeFinding(domain, alias, b.name, b, nowIso));
  });
  return findings;
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
    // (3) 데모
    isDemo = true;
    status = "no_source";
    source = "데모 데이터 (모니터링 대상 미설정)";
    note =
      "HIBP_API_KEY 또는 모니터링 대상 계정(accounts)이 설정되지 않아 예시(데모) 데이터를 표시합니다. " +
      "data/security/monitor_config.local.json 에 회사 계정 이메일을 넣으면(무료 XposedOrNot) 실데이터로 전환됩니다.";
    findings = buildDemoFindings(domains, nowIso);
    console.log("[monitor] 소스 미설정 → 데모 데이터 생성");
  }

  // 신규 표시 + 출처 기록 (실데이터 한정 — 데모는 항상 false)
  for (const f of findings) {
    f.isNew = !isDemo && !prevIds.has(f.id);
    f.source = source;
  }
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
      endpoint: HIBP_API_KEY ? "haveibeenpwned.com /api/v3/breacheddomain" : "api.xposedornot.com /v1/check-email",
      count: findings.length,
      scannedAt: nowIso,
    },
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

  const scan = { generatedAt: nowIso, source, status, isDemo, domains, findings, summary, history, note, infostealer, sources };

  await writeFile(latestFile, JSON.stringify(scan, null, 2), "utf8");
  await writeFile(join(historyDir, `breach_scan_${todayStamp()}.json`), JSON.stringify(scan, null, 2), "utf8");
  await writeGenerated(scan);
  await loadSupabase(scan);

  console.log(
    `[monitor] 완료 — 총 ${summary.total}건 (신규 ${summary.newCount}, ` +
      `critical ${summary.bySeverity.critical}, high ${summary.bySeverity.high})` +
      (isDemo ? " [데모]" : "")
  );
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});

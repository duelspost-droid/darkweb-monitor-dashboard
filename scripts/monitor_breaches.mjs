// 다크웹/유출 계정 모니터링 수집기.
//
// 동작 개요:
//  1) data/security/monitor_config.json 의 회사 도메인을 읽는다.
//  2) HIBP_API_KEY 가 있으면 Have I Been Pwned 도메인 검색 API 로
//     해당 도메인 계정의 유출 여부를 조회한다(평문 비밀번호는 받지 않음).
//  3) 공개 breaches 메타데이터로 유출 사건명·일자·노출 항목·심각도를 보강한다.
//  4) 직전 스캔과 비교해 신규 항목을 표시하고, 이력 타임라인을 누적한다.
//  5) 결과를 마스킹된 형태로만:
//       - data/security/latest_breach_scan.json (원본 기록)
//       - data/security/history/breach_scan_<stamp>.json (이력)
//       - lib/data/generated/breachMonitor.ts (정적 사이트가 임포트)
//     로 저장한다.
//
// 중요(개인정보): 계정은 항상 마스킹(jo***@domain)으로만 저장한다.
// 평문 비밀번호·전체 이메일·기타 개인식별자는 절대 저장하지 않는다.
//
// API 키가 없으면 페이지가 비지 않도록 "데모 데이터"(isDemo=true)를 생성한다.
// 실제 운영에서는 HIBP_API_KEY 를 .env.local / GitHub Secret 에 등록하면 실데이터로 전환된다.

import { mkdir, readFile, writeFile, readdir } from "node:fs/promises";
import { createHash } from "node:crypto";
import { join } from "node:path";

const root = process.cwd();
const securityDir = join(root, "data", "security");
const historyDir = join(securityDir, "history");
const generatedFile = join(root, "lib", "data", "generated", "breachMonitor.ts");
const configFile = join(securityDir, "monitor_config.json");
const latestFile = join(securityDir, "latest_breach_scan.json");

const HIBP_API_KEY = process.env.HIBP_API_KEY?.trim();
const HIBP_BASE = "https://haveibeenpwned.com/api/v3";
const USER_AGENT = "foreign-resident-finance-dashboard-breach-monitor";

// HIBP 노출 항목(영문) → 한글 표시 매핑(미정의는 원문 유지).
const DATA_CLASS_KO = {
  "Email addresses": "이메일",
  "Passwords": "비밀번호",
  "Usernames": "사용자명",
  "Names": "이름",
  "Phone numbers": "전화번호",
  "Physical addresses": "주소",
  "IP addresses": "IP 주소",
  "Dates of birth": "생년월일",
  "Genders": "성별",
  "Credit cards": "신용카드",
  "Bank account numbers": "계좌번호",
  "Security questions and answers": "보안 질문/답변",
  "Auth tokens": "인증 토큰",
  "Geographic locations": "위치 정보",
  "Job titles": "직책",
  "Employers": "직장",
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

function todayStamp() {
  return new Date().toISOString().replace(/[:.]/g, "-");
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

async function hibpFetch(path) {
  const res = await fetch(`${HIBP_BASE}${path}`, {
    headers: {
      "hibp-api-key": HIBP_API_KEY,
      "user-agent": USER_AGENT,
    },
  });
  if (res.status === 404) return null; // 유출 없음
  if (!res.ok) {
    throw new Error(`HIBP ${path} → HTTP ${res.status} ${(await res.text()).slice(0, 200)}`);
  }
  if (res.status === 204) return null;
  return res.json();
}

// 공개 breaches 메타데이터(키 불필요)로 사건명 → {title, date, dataClasses} 사전 구성.
async function loadBreachCatalog() {
  try {
    const res = await fetch(`${HIBP_BASE}/breaches`, { headers: { "user-agent": USER_AGENT } });
    if (!res.ok) return new Map();
    const arr = await res.json();
    const map = new Map();
    for (const b of arr) {
      map.set(b.Name, {
        title: b.Title ?? b.Name,
        date: b.BreachDate ?? "",
        dataClasses: Array.isArray(b.DataClasses) ? b.DataClasses : [],
      });
    }
    return map;
  } catch {
    return new Map();
  }
}

function koDataClasses(list) {
  return list.map((dc) => DATA_CLASS_KO[dc] ?? dc);
}

// HIBP 도메인 검색 결과(alias → [breachName...]) → 정규화된 finding 배열.
function buildFindingsFromDomainMap(domain, aliasMap, catalog, nowIso) {
  const findings = [];
  for (const [alias, breachNames] of Object.entries(aliasMap || {})) {
    for (const breachName of breachNames) {
      const meta = catalog.get(breachName) || { title: breachName, date: "", dataClasses: [] };
      findings.push({
        id: findingId(domain, alias, breachName),
        accountMasked: `${maskLocalPart(alias)}@${domain}`,
        domain,
        breachName,
        breachTitle: meta.title,
        breachDate: meta.date,
        dataClasses: koDataClasses(meta.dataClasses),
        severity: severityForDataClasses(meta.dataClasses),
        isNew: false,
        discoveredAt: nowIso,
      });
    }
  }
  return findings;
}

// ── 데모 데이터(키 미설정 시) ──────────────────────────────────────────────
// 잘 알려진 유출 사건 메타데이터로 그럴듯한 예시를 생성한다(isDemo=true 로 표시).
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
    // 일부 계정에 1~2개 유출을 배정
    const picks = demoBreaches.slice(i % 3, (i % 3) + 1 + (i % 2));
    for (const b of picks) {
      findings.push({
        id: findingId(domain, alias, b.name),
        accountMasked: `${maskLocalPart(alias)}@${domain}`,
        domain,
        breachName: b.name,
        breachTitle: b.title,
        breachDate: b.date,
        dataClasses: koDataClasses(b.dataClasses),
        severity: severityForDataClasses(b.dataClasses),
        isNew: false,
        discoveredAt: nowIso,
      });
    }
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
    const rows = scan.findings.map((f) => ({
      finding_id: f.id,
      account_masked: f.accountMasked,
      domain: f.domain,
      breach_name: f.breachName,
      breach_title: f.breachTitle,
      breach_date: f.breachDate || null,
      data_classes: f.dataClasses,
      severity: f.severity,
      discovered_at: f.discoveredAt,
    }));
    if (rows.length === 0) return;
    const res = await fetch(`${url}/rest/v1/breach_findings?on_conflict=finding_id`, {
      method: "POST",
      headers: {
        apikey: key,
        Authorization: `Bearer ${key}`,
        "Content-Type": "application/json",
        Prefer: "resolution=merge-duplicates,return=minimal",
      },
      body: JSON.stringify(rows),
    });
    if (res.ok) console.log(`[supabase] breach_findings upsert ${rows.length}행`);
    else console.warn(`[supabase] 적재 실패 HTTP ${res.status} (테이블 미생성일 수 있음 — 008 마이그레이션 확인)`);
  } catch (err) {
    console.warn(`[supabase] 적재 건너뜀: ${err.message}`);
  }
}

async function main() {
  await ensureDirs();
  const nowIso = new Date().toISOString();
  const config = await readJson(configFile, { domains: [], extraAccounts: [], minSeverity: "low" });
  const domains = Array.isArray(config.domains) ? config.domains.filter(Boolean) : [];

  const previous = await readJson(latestFile, null);
  const prevIds = new Set((previous?.findings ?? []).map((f) => f.id));
  const prevHistory = Array.isArray(previous?.history) ? previous.history : [];

  let findings = [];
  let status = "ok";
  let isDemo = false;
  let source = "Have I Been Pwned (도메인 검색 API)";
  let note;

  if (!HIBP_API_KEY) {
    isDemo = true;
    status = "no_api_key";
    source = "데모 데이터 (HIBP_API_KEY 미설정)";
    note =
      "HIBP_API_KEY 가 설정되지 않아 예시(데모) 데이터를 표시합니다. " +
      ".env.local 또는 GitHub Secret 에 HIBP_API_KEY 를 등록하고 HIBP 대시보드에서 도메인 소유를 검증하면 실제 유출 데이터로 전환됩니다.";
    findings = buildDemoFindings(domains, nowIso);
    console.log("[monitor] HIBP_API_KEY 미설정 → 데모 데이터 생성");
  } else {
    try {
      const catalog = await loadBreachCatalog();
      for (const domain of domains) {
        console.log(`[monitor] HIBP 도메인 검색: ${domain}`);
        const aliasMap = await hibpFetch(`/breacheddomain/${encodeURIComponent(domain)}`);
        findings.push(...buildFindingsFromDomainMap(domain, aliasMap, catalog, nowIso));
      }
      // 개별 추가 계정(extraAccounts)도 조회
      for (const acct of config.extraAccounts ?? []) {
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
      // 실패 시 직전 결과를 보존(회귀 방지)
      if (previous?.findings?.length) {
        findings = previous.findings.map((f) => ({ ...f, isNew: false }));
        source = previous.source;
      }
    }
  }

  // 신규 표시 (실데이터 한정 — 데모는 항상 false)
  for (const f of findings) {
    f.isNew = !isDemo && !prevIds.has(f.id);
  }
  findings = sortFindings(findings);

  const summary = summarize(findings, domains);
  const history = [
    ...prevHistory.slice(-29),
    { scannedAt: nowIso, total: summary.total, newCount: summary.newCount },
  ];

  const scan = {
    generatedAt: nowIso,
    source,
    status,
    isDemo,
    domains,
    findings,
    summary,
    history,
    note,
  };

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

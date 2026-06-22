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
const UA = "darkweb-monitor-dashboard-breach-monitor";

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
  const res = await fetch(`${HIBP_BASE}/breacheddomain/${encodeURIComponent(domain)}`, {
    headers: { "hibp-api-key": HIBP_API_KEY!, "user-agent": UA },
  });
  if (res.status === 404 || res.status === 204) return null;
  if (!res.ok) throw new Error(`HIBP ${domain} → HTTP ${res.status}`);
  return res.json();
}

interface Finding {
  finding_id: string; account_masked: string; domain: string; breach_name: string;
  breach_title: string; breach_date: string | null; data_classes: string[]; severity: string;
  password_risk?: string; industry?: string; reference_url?: string; breach_logo?: string;
}
async function mkFinding(domain: string, alias: string, name: string, meta: Catalog[string], nowIso: string): Promise<Finding & { is_new: boolean; discovered_at: string }> {
  return {
    finding_id: await sha1Hex(`${domain}|${alias}|${name}`),
    account_masked: `${maskLocal(alias)}@${domain}`,
    domain, breach_name: name, breach_title: meta?.title || name,
    breach_date: meta?.date || null, data_classes: koClasses(meta?.dataClasses ?? []),
    severity: severityFor(meta?.dataClasses ?? []),
    password_risk: meta?.passwordRisk, industry: meta?.industry,
    reference_url: meta?.referenceURL, breach_logo: meta?.logo,
    is_new: false, discovered_at: nowIso,
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
  let findings: (Finding & { is_new: boolean; discovered_at: string })[] = [];
  let status = "ok";
  let source = "";
  let note: string | null = null;

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

  // is_new 계산 (정상 스캔 한정)
  if (status === "ok") {
    const existing = await sbGetExistingIds();
    for (const f of findings) f.is_new = !existing.has(f.finding_id);
  }

  // 적재 (정상 스캔만 DB 갱신; 오류 시 기존 데이터 보존)
  if (status === "ok") {
    const rows = findings.map((f) => ({ ...f, last_scan_tag: scanTag }));
    await sbUpsert(rows);
    await sbDeleteStale(scanTag);
  }

  const summary = { critical: 0, high: 0, medium: 0, low: 0 };
  let newCount = 0;
  for (const f of findings) { summary[f.severity as keyof typeof summary]++; if (f.is_new) newCount++; }

  await sbInsertScanRun({
    scanned_at: nowIso, source, status, is_demo: false,
    total: findings.length, new_count: newCount,
    critical: summary.critical, high: summary.high, medium: summary.medium, low: summary.low,
    domains: [...new Set([...MONITORED_DOMAINS, ...findings.map((f) => f.domain)])],
    note,
  });

  return new Response(JSON.stringify({
    ok: status !== "error", status, source, total: findings.length, newCount, summary, note,
  }), { headers: { "Content-Type": "application/json" } });
});

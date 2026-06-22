// ⚠️ 내부 전용(INTERNAL ONLY) — 공개 대시보드/Supabase/git 에 올리지 않는다.
//
// 회사가 통제권을 가진 "임직원 회사 계정"에 한해 Hudson Rock Cavalier(무료)로
// 개별 인포스틸러 감염 여부·상세(PC명·OS·부분IP·감염일·부분비번)를 점검한다.
//
// 입력: data/security/monitor_config.local.json 의 accounts (회사 소유 계정만 넣을 것)
// 출력: data/security/employee_stealer_report.local.json (★gitignore — 절대 커밋 금지)
//        + 콘솔 요약
//
// 개인정보 주의:
//  - 고객 계정은 넣지 말 것. 회사 소유(임직원/역할) 계정만.
//  - 결과는 민감(부분 비번·PC명). 로컬에서만 보고 안전하게 폐기.
//  - Cavalier 가 IP·비번을 이미 부분 마스킹해 반환한다.

import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";

const root = process.cwd();
const localConfig = join(root, "data", "security", "monitor_config.local.json");
const outFile = join(root, "data", "security", "employee_stealer_report.local.json");
const CAVALIER = "https://cavalier.hudsonrock.com/api/json/v2/osint-tools/search-by-email";
const UA = "darkweb-monitor-dashboard-breach-monitor";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function readJson(p, fb) {
  try { return JSON.parse(await readFile(p, "utf8")); } catch { return fb; }
}

async function checkEmail(email) {
  try {
    const res = await fetch(`${CAVALIER}?email=${encodeURIComponent(email)}`, { headers: { "user-agent": UA } });
    if (!res.ok) return { ok: false, status: res.status };
    const d = await res.json();
    const stealers = Array.isArray(d?.stealers) ? d.stealers : [];
    return { ok: true, compromised: stealers.length > 0, stealers };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}

async function main() {
  const cfg = await readJson(localConfig, { accounts: [] });
  const accounts = (cfg.accounts ?? []).filter(Boolean);
  if (!accounts.length) {
    console.error("monitor_config.local.json 에 accounts(회사 소유 계정)가 없습니다.");
    process.exitCode = 1;
    return;
  }

  console.log(`\n⚠️  내부 전용 임직원 인포스틸러 점검 — ${accounts.length}개 계정 (회사 소유 한정)\n`);
  const nowIso = new Date().toISOString();
  const report = [];
  for (const email of accounts) {
    const r = await checkEmail(email);
    if (!r.ok) {
      console.log(`  ?  ${email}  — 조회 실패(${r.status ?? r.error})`);
      report.push({ email, checkedAt: nowIso, status: "error" });
    } else if (!r.compromised) {
      console.log(`  ✓  ${email}  — 감염 없음`);
      report.push({ email, checkedAt: nowIso, compromised: false, stealers: [] });
    } else {
      console.log(`  🔴 ${email}  — 감염 ${r.stealers.length}건`);
      for (const s of r.stealers) {
        console.log(
          `       └ PC:${s.computer_name ?? "?"} | ${s.operating_system ?? "?"} | IP:${s.ip ?? "?"} | ` +
            `감염일:${(s.date_compromised ?? "").slice(0, 10)} | 서비스(사내/개인):${s.total_corporate_services ?? 0}/${s.total_user_services ?? 0}`
        );
        if (Array.isArray(s.top_passwords) && s.top_passwords.length)
          console.log(`         부분 비번(마스킹): ${s.top_passwords.join(", ")}`);
      }
      report.push({
        email,
        checkedAt: nowIso,
        compromised: true,
        stealers: r.stealers.map((s) => ({
          computer_name: s.computer_name,
          operating_system: s.operating_system,
          ip: s.ip,
          date_compromised: s.date_compromised,
          total_corporate_services: s.total_corporate_services,
          total_user_services: s.total_user_services,
          top_passwords: s.top_passwords,
        })),
      });
    }
    await sleep(400);
  }

  await writeFile(outFile, JSON.stringify({ generatedAt: nowIso, report }, null, 2), "utf8");
  const hit = report.filter((r) => r.compromised).length;
  console.log(`\n완료 — 감염 ${hit}건 / 총 ${accounts.length}건. 상세: ${outFile} (gitignore, 내부 전용)\n`);
}

main().catch((e) => { console.error(e); process.exitCode = 1; });

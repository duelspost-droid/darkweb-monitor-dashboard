import {
  AlertTriangle,
  CalendarClock,
  Globe,
  Info,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
} from "lucide-react";
import { PageHero } from "@/components/ui/PageHero";
import { Panel } from "@/components/ui/Panel";
import { StatTile } from "@/components/ui/StatTile";
import { BarList } from "@/components/ui/BarList";
import { breachScan } from "@/lib/data/generated/breachMonitor";
import type { BreachSeverity } from "@/lib/types/breachMonitor";

const SEVERITY_META: Record<BreachSeverity, { label: string; color: string; chip: string }> = {
  critical: { label: "심각", color: "#be123c", chip: "bg-rose-100 text-rose-700 border-rose-300" },
  high: { label: "높음", color: "#b45309", chip: "bg-amber-100 text-amber-700 border-amber-300" },
  medium: { label: "보통", color: "#3157a4", chip: "bg-sky-100 text-sky-700 border-sky-300" },
  low: { label: "낮음", color: "#0f766e", chip: "bg-teal-100 text-teal-700 border-teal-300" },
};

function fmtDate(iso: string) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleDateString("ko-KR", { year: "numeric", month: "2-digit", day: "2-digit" });
}

export default function SecurityPage() {
  const scan = breachScan;
  const { summary } = scan;

  const severityItems = (Object.keys(SEVERITY_META) as BreachSeverity[])
    .map((sev) => ({
      label: SEVERITY_META[sev].label,
      value: summary.bySeverity[sev] ?? 0,
      color: SEVERITY_META[sev].color,
      display: String(summary.bySeverity[sev] ?? 0),
    }))
    .filter((it) => it.value > 0);

  const domainItems = summary.byDomain
    .map((d) => ({ label: d.domain, value: d.count, display: `${d.count}건` }))
    .sort((a, b) => b.value - a.value);

  const historyRecent = [...scan.history].slice(-12).reverse();

  return (
    <div className="space-y-7 pb-14">
      <PageHero
        kicker="보안 · 다크웹 유출 모니터링"
        title="회사 계정 유출 모니터링"
        description="매일 자동으로 유출 인텔리전스(Have I Been Pwned)를 조회해 회사 도메인 계정이 다크웹·유출 데이터셋에 노출됐는지 추적합니다. 계정은 마스킹된 형태로만 기록합니다."
        right={
          <span className="inline-flex items-center gap-1.5 rounded-full border border-white/20 bg-white/10 px-3 py-1.5 text-xs font-semibold text-white">
            <CalendarClock size={13} aria-hidden /> 최근 스캔 {fmtDate(scan.generatedAt)}
          </span>
        }
      />

      {/* 데모/상태 배너 */}
      {scan.isDemo ? (
        <div className="flex items-start gap-3 rounded-xl border border-amber-300 bg-amber-50 p-4">
          <Info size={18} className="mt-0.5 shrink-0 text-amber-600" aria-hidden />
          <div className="text-sm leading-6 text-amber-800">
            <strong className="font-bold">데모 데이터입니다.</strong> {scan.note}
          </div>
        </div>
      ) : scan.status === "error" ? (
        <div className="flex items-start gap-3 rounded-xl border border-rose-300 bg-rose-50 p-4">
          <AlertTriangle size={18} className="mt-0.5 shrink-0 text-rose-600" aria-hidden />
          <div className="text-sm leading-6 text-rose-800">
            <strong className="font-bold">최근 조회 실패.</strong> {scan.note} (직전 결과를 표시 중)
          </div>
        </div>
      ) : null}

      {/* KPI */}
      <div className="stat-grid">
        <StatTile
          label="모니터링 도메인"
          value={scan.domains.length}
          unit="개"
          icon={<Globe size={18} />}
          accent="#3157a4"
          sub={scan.domains.join(", ") || "미설정"}
        />
        <StatTile
          label="유출 노출 계정"
          value={summary.total}
          unit="건"
          icon={<ShieldAlert size={18} />}
          accent="#be123c"
          trend={{ label: summary.total > 0 ? "조치 필요" : "노출 없음", dir: summary.total > 0 ? "down" : "up" }}
          sub="마스킹 집계"
        />
        <StatTile
          label="이번 스캔 신규"
          value={summary.newCount}
          unit="건"
          icon={<Sparkles size={18} />}
          accent="#b45309"
          trend={{ label: summary.newCount > 0 ? "신규 발견" : "변동 없음", dir: summary.newCount > 0 ? "down" : "neutral" }}
          sub="직전 대비"
        />
        <StatTile
          label="심각(Critical)"
          value={summary.bySeverity.critical}
          unit="건"
          icon={<AlertTriangle size={18} />}
          accent="#be123c"
          trend={{ label: "비밀번호·금융정보 노출", dir: summary.bySeverity.critical > 0 ? "down" : "up" }}
          sub="우선 대응 대상"
        />
      </div>

      {/* 분포 2열 */}
      <section className="grid gap-4 lg:grid-cols-2">
        <Panel title="심각도 분포" subtitle="노출된 데이터 분류 기반 위험도">
          {severityItems.length ? (
            <BarList items={severityItems} unit="건" />
          ) : (
            <p className="py-6 text-center text-sm text-muted">노출된 계정이 없습니다.</p>
          )}
        </Panel>
        <Panel title="도메인별 노출" subtitle="모니터링 대상 도메인별 유출 건수">
          {domainItems.length ? (
            <BarList items={domainItems} />
          ) : (
            <p className="py-6 text-center text-sm text-muted">데이터가 없습니다.</p>
          )}
        </Panel>
      </section>

      {/* 유출 상세 테이블 */}
      <Panel
        title="유출 계정 상세"
        subtitle="계정은 마스킹 처리됩니다. 신규 항목은 상단에 표시됩니다."
        right={
          <span className="chip chip-neutral">총 {summary.total}건</span>
        }
        bodyClassName="p-0"
      >
        <div className="overflow-x-auto">
          <table className="w-full min-w-[720px] text-sm">
            <thead>
              <tr className="border-b border-slate-200 text-left text-xs font-semibold uppercase tracking-wide text-muted">
                <th className="px-5 py-3">계정 (마스킹)</th>
                <th className="px-5 py-3">유출 사건</th>
                <th className="px-5 py-3">유출 일자</th>
                <th className="px-5 py-3">노출 항목</th>
                <th className="px-5 py-3">심각도</th>
              </tr>
            </thead>
            <tbody>
              {scan.findings.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-5 py-10 text-center text-muted">
                    노출된 계정이 없습니다. 👍
                  </td>
                </tr>
              ) : (
                scan.findings.map((f) => {
                  const sev = SEVERITY_META[f.severity];
                  return (
                    <tr key={f.id} className="border-b border-slate-100 last:border-0 hover:bg-slate-50">
                      <td className="px-5 py-3 font-mono font-semibold text-ink">
                        <span className="inline-flex items-center gap-2">
                          {f.isNew && (
                            <span className="rounded-full bg-amber-100 px-1.5 py-0.5 text-[10px] font-bold text-amber-700">
                              NEW
                            </span>
                          )}
                          {f.accountMasked}
                        </span>
                      </td>
                      <td className="px-5 py-3 text-slate-700">{f.breachTitle}</td>
                      <td className="px-5 py-3 font-mono text-xs text-muted">{f.breachDate || "—"}</td>
                      <td className="px-5 py-3">
                        <div className="flex flex-wrap gap-1">
                          {f.dataClasses.slice(0, 4).map((dc) => (
                            <span
                              key={dc}
                              className="rounded border border-slate-200 bg-slate-50 px-1.5 py-0.5 text-[11px] text-slate-600"
                            >
                              {dc}
                            </span>
                          ))}
                          {f.dataClasses.length > 4 && (
                            <span className="text-[11px] text-muted">+{f.dataClasses.length - 4}</span>
                          )}
                        </div>
                      </td>
                      <td className="px-5 py-3">
                        <span
                          className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-semibold ${sev.chip}`}
                        >
                          {sev.label}
                        </span>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </Panel>

      {/* 스캔 이력 + 동작 방식 */}
      <section className="grid gap-4 lg:grid-cols-2">
        <Panel title="스캔 이력" subtitle="최근 스캔별 노출 건수 추이">
          {historyRecent.length ? (
            <ul className="space-y-2">
              {historyRecent.map((h) => (
                <li
                  key={h.scannedAt}
                  className="flex items-center justify-between rounded-lg border border-slate-100 bg-slate-50 px-3 py-2 text-sm"
                >
                  <span className="font-mono text-xs text-muted">{fmtDate(h.scannedAt)}</span>
                  <span className="text-slate-700">
                    총 <strong className="text-ink">{h.total}</strong>건
                    {h.newCount > 0 && (
                      <span className="ml-2 rounded-full bg-amber-100 px-1.5 py-0.5 text-[11px] font-bold text-amber-700">
                        신규 {h.newCount}
                      </span>
                    )}
                  </span>
                </li>
              ))}
            </ul>
          ) : (
            <p className="py-6 text-center text-sm text-muted">이력이 없습니다.</p>
          )}
        </Panel>

        <Panel title="동작 방식 · 운영 안내" subtitle="합법적 유출 인텔리전스 기반 모니터링">
          <ul className="space-y-3 text-sm leading-6 text-slate-700">
            <li className="flex gap-2">
              <ShieldCheck size={16} className="mt-0.5 shrink-0 text-teal-600" aria-hidden />
              <span>
                다크웹 마켓·포럼을 직접 크롤링하지 않고, 검증된 유출 인텔리전스 API
                (Have I Been Pwned 도메인 검색)로 <strong>유출 사실만</strong> 조회합니다. 평문
                비밀번호는 받지 않습니다.
              </span>
            </li>
            <li className="flex gap-2">
              <ShieldCheck size={16} className="mt-0.5 shrink-0 text-teal-600" aria-hidden />
              <span>
                매일 자동 배치(<code className="rounded bg-slate-100 px-1">npm run security:scan</code>)로
                갱신되며, 결과는 마스킹된 계정으로만 기록됩니다.
              </span>
            </li>
            <li className="flex gap-2">
              <Info size={16} className="mt-0.5 shrink-0 text-sky-600" aria-hidden />
              <span>
                실데이터 전환: <code className="rounded bg-slate-100 px-1">HIBP_API_KEY</code> 등록 +
                HIBP 대시보드에서 도메인 소유 검증. 대상 도메인은{" "}
                <code className="rounded bg-slate-100 px-1">data/security/monitor_config.json</code>에서
                관리합니다.
              </span>
            </li>
            <li className="flex gap-2">
              <AlertTriangle size={16} className="mt-0.5 shrink-0 text-amber-600" aria-hidden />
              <span>
                유출이 확인된 계정은 즉시 비밀번호 재설정·MFA 적용을 권고하고, 동일 비밀번호를
                재사용한 다른 서비스도 점검해야 합니다.
              </span>
            </li>
          </ul>
          <p className="mt-4 border-t border-slate-100 pt-3 text-xs text-muted">
            출처: {scan.source}
          </p>
        </Panel>
      </section>
    </div>
  );
}

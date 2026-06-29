"use client";

import { useCallback, useEffect, useState } from "react";
import {
  AlertTriangle,
  Bug,
  CalendarClock,
  Database,
  Download,
  Globe,
  Info,
  LogOut,
  Lock,
  Monitor,
  KeyRound,
  MapPin,
  FileWarning,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
} from "lucide-react";
import type { Session } from "@supabase/supabase-js";
import { PageHero } from "@/components/ui/PageHero";
import { Panel } from "@/components/ui/Panel";
import { StatTile } from "@/components/ui/StatTile";
import { BarList } from "@/components/ui/BarList";
import { supabase, supabaseConfigured, adminEmail } from "@/lib/supabase/browserClient";
import type { BreachScan, BreachSeverity, InfostealerFinding, InfostealerHost } from "@/lib/types/breachMonitor";

const SEVERITY_META: Record<BreachSeverity, { label: string; color: string; chip: string }> = {
  critical: { label: "심각", color: "#be123c", chip: "bg-rose-100 text-rose-700 border-rose-300" },
  high: { label: "높음", color: "#b45309", chip: "bg-amber-100 text-amber-700 border-amber-300" },
  medium: { label: "보통", color: "#3157a4", chip: "bg-sky-100 text-sky-700 border-sky-300" },
  low: { label: "낮음", color: "#0f766e", chip: "bg-teal-100 text-teal-700 border-teal-300" },
};
const SEVERITY_RANK: Record<string, number> = { low: 0, medium: 1, high: 2, critical: 3 };

// 모니터링 도메인 → 계열사명 (표시용).
const INSTITUTIONS: Record<string, string> = {
  "jbfg.com": "JB금융지주",
  "jbbank.co.kr": "전북은행",
  "kjbank.com": "광주은행",
  "wooricap.com": "JB우리캐피탈",
};

// 탈취 URL 유형 분류 (Hudson Rock 은 Employee/User/Third-party 등 대소문자 혼재로 반환).
function urlKind(type?: string) {
  const t = (type ?? "").toLowerCase();
  if (t.startsWith("emp")) return { label: "직원", cls: "bg-rose-100 text-rose-700" };
  if (t.startsWith("third") || t.includes("party")) return { label: "서드파티", cls: "bg-violet-100 text-violet-700" };
  return { label: "고객", cls: "bg-sky-100 text-sky-700" };
}

// 계정 표시 — *@domain(특정 계정 없는 도메인 단위 노출, 예: GitHub 코드 노출)은
// 마스킹 '*' 대신 도메인 + '도메인 노출' 배지로 제대로 보여준다. 그 외는 식별 전체 그대로.
function AcctLabel({ accountMasked, domain }: { accountMasked: string; domain: string }) {
  if (accountMasked.startsWith("*@")) {
    return (
      <>
        <span>{domain}</span>
        <span className="rounded bg-slate-100 px-1 py-0.5 text-[10px] font-sans font-semibold text-slate-500" title="특정 계정이 아닌 도메인 단위 노출(예: GitHub 코드)">도메인 노출</span>
      </>
    );
  }
  return <>{accountMasked}</>;
}

// 계정별로 유출(COMB·유출이력·GitHub 등)을 묶어 "이 계정 → 어디서·언제" 형태로 보여준다.
type GroupingFinding = {
  id: string; accountMasked: string; domain: string;
  breachTitle: string; breachDate: string; dataClasses: string[];
  severity: keyof typeof SEVERITY_META; isNew: boolean; source: string; referenceUrl?: string;
  status?: string; remediationNote?: string; remediatedBy?: string; remediatedAt?: string;
};

// 조치 상태 메타
const STATUS_META: Record<string, { label: string; cls: string }> = {
  open: { label: "미조치", cls: "border-slate-300 bg-slate-100 text-slate-600" },
  remediated: { label: "조치완료", cls: "border-teal-300 bg-teal-100 text-teal-700" },
  dismissed: { label: "이상없음", cls: "border-sky-300 bg-sky-100 text-sky-700" },
};

// 자동 조치의견 — 노출 유형·인포스틸러 여부 기반 권고.
function suggestAction(hasStealer: boolean, dataClasses: Set<string>): string {
  if (hasStealer)
    return "감염 추정 PC 격리·백신 정밀검사 → 해당 계정 비밀번호 즉시 재설정 + MFA → 활성 세션 강제 로그아웃. 동일 비밀번호 재사용 서비스 점검.";
  if (dataClasses.has("신용카드") || dataClasses.has("계좌번호"))
    return "금융정보 노출 — 카드/계좌 모니터링·재발급 검토, 본인 통지 및 비밀번호 재설정.";
  if (dataClasses.has("비밀번호"))
    return "비밀번호 즉시 재설정 + MFA 적용. 동일/유사 비밀번호를 쓴 다른 서비스도 점검.";
  return "노출 항목 확인 후 비밀번호 재설정·계정 점검 권고.";
}

// 계정(그룹) 단위 조치 컨트롤 — 상태 변경 + 메모를 set_remediation RPC 로 기록.
function RemediationControls({
  account, status, note, by, at, suggestion, onChanged,
}: { account: string; status: string; note?: string; by?: string; at?: string; suggestion: string; onChanged: () => void }) {
  const [draft, setDraft] = useState(note ?? "");
  const [busy, setBusy] = useState("");
  const [err, setErr] = useState("");
  const cur = STATUS_META[status] ?? STATUS_META.open;
  async function apply(s: string) {
    setBusy(s); setErr("");
    const { error } = await supabase.rpc("set_remediation", { p_account: account, p_status: s, p_note: draft || null });
    setBusy("");
    if (error) setErr("저장 실패: " + error.message);
    else onChanged();
  }
  return (
    <div className="border-t border-slate-100 bg-slate-50/70 px-4 py-3">
      <div className="mb-2 flex flex-wrap items-center gap-2 text-xs">
        <span className="font-semibold text-muted">조치 상태</span>
        <span className={`rounded-full border px-2 py-0.5 font-semibold ${cur.cls}`}>{cur.label}</span>
        {by && at && <span className="text-[11px] text-muted">· {by} · {fmtDate(at)}</span>}
      </div>
      <div className="mb-2 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-[12px] leading-5 text-amber-900">
        <b>조치의견:</b> {suggestion}
      </div>
      <textarea
        value={draft} onChange={(e) => setDraft(e.target.value)} rows={2}
        placeholder="조치 내역/메모 (예: 6/25 비번 재설정·MFA 적용 / 또는 '오탐 — 이상없음' 사유)"
        className="mb-2 w-full rounded-lg border border-slate-300 px-2.5 py-1.5 text-xs outline-none focus:border-rose-400"
      />
      <div className="flex flex-wrap items-center gap-2">
        <button onClick={() => apply("remediated")} disabled={!!busy} className="rounded-lg bg-teal-600 px-3 py-1.5 text-xs font-bold text-white hover:bg-teal-700 disabled:opacity-50">{busy === "remediated" ? "저장…" : "조치완료"}</button>
        <button onClick={() => apply("dismissed")} disabled={!!busy} className="rounded-lg bg-sky-600 px-3 py-1.5 text-xs font-bold text-white hover:bg-sky-700 disabled:opacity-50">{busy === "dismissed" ? "저장…" : "이상없음"}</button>
        <button onClick={() => apply("open")} disabled={!!busy} className="rounded-lg border border-slate-300 px-3 py-1.5 text-xs font-semibold text-slate-600 hover:bg-slate-100 disabled:opacity-50">{busy === "open" ? "저장…" : "미조치로"}</button>
        {err && <span className="self-center text-[11px] font-semibold text-rose-600">{err}</span>}
      </div>
    </div>
  );
}

type Exp = { id: string; title: string; date: string; dataClasses: string[]; source: string; referenceUrl?: string };
type Grp = { accountMasked: string; domain: string; isNew: boolean; hasStealer: boolean; severity: keyof typeof SEVERITY_META; sevRank: number; exposures: Exp[]; status: string; note?: string; by?: string; at?: string };

function AccountGroupedFindings({ findings, onChanged }: { findings: GroupingFinding[]; onChanged: () => void }) {
  const [query, setQuery] = useState("");
  const [tab, setTab] = useState<"pending" | "done">("pending");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [bulkBusy, setBulkBusy] = useState("");
  const [bulkErr, setBulkErr] = useState("");

  // 재스캔/리로드로 사라진 계정 키를 selected·expanded 에서 정리(유령 선택 방지)
  useEffect(() => {
    const valid = new Set(findings.map((f) => f.accountMasked));
    setSelected((s) => { const n = new Set([...s].filter((k) => valid.has(k))); return n.size === s.size ? s : n; });
    setExpanded((s) => { const n = new Set([...s].filter((k) => valid.has(k))); return n.size === s.size ? s : n; });
  }, [findings]);

  const map = new Map<string, Grp>();
  for (const f of findings) {
    let g = map.get(f.accountMasked);
    if (!g) { g = { accountMasked: f.accountMasked, domain: f.domain, isNew: false, hasStealer: false, severity: f.severity, sevRank: -1, exposures: [], status: "open" }; map.set(f.accountMasked, g); }
    if (f.status && f.status !== "open") { g.status = f.status; g.note = f.remediationNote; g.by = f.remediatedBy; g.at = f.remediatedAt; }
    else if (f.remediationNote && !g.note) { g.note = f.remediationNote; }
    if (f.isNew) g.isNew = true;
    if (/Hudson Rock/i.test(f.source) || (f.dataClasses ?? []).includes("인포스틸러 감염")) g.hasStealer = true;
    const rank = SEVERITY_RANK[f.severity] ?? 0;
    if (rank > g.sevRank) { g.sevRank = rank; g.severity = f.severity; }
    g.exposures.push({ id: f.id, title: f.breachTitle, date: f.breachDate, dataClasses: f.dataClasses, source: f.source, referenceUrl: f.referenceUrl });
  }
  const groups = [...map.values()].sort((a, b) => {
    if (a.hasStealer !== b.hasStealer) return a.hasStealer ? -1 : 1;
    if (a.isNew !== b.isNew) return a.isNew ? -1 : 1;
    if (b.sevRank !== a.sevRank) return b.sevRank - a.sevRank;
    return b.exposures.length - a.exposures.length;
  });
  for (const g of groups) g.exposures.sort((x, y) => (y.date || "").localeCompare(x.date || ""));

  // 칩 카운트는 "검색 적용 후" 집합 기준(상태필터는 제외)으로 집계 → 보이는 목록과 숫자 일치
  const q = query.trim().toLowerCase();
  const searchMatched = groups.filter((g) =>
    !q || g.accountMasked.toLowerCase().includes(q) || g.domain.toLowerCase().includes(q),
  );
  const counts: Record<string, number> = { all: searchMatched.length, open: 0, remediated: 0, dismissed: 0 };
  for (const g of searchMatched) counts[g.status] = (counts[g.status] ?? 0) + 1;

  // 두 갈래: 조치 필요(open) 큐 ↔ 조치 완료(remediated·dismissed) 내역. 조치하면 자동으로 큐에서 빠져 내역으로.
  const pendingCount = counts.open ?? 0;
  const doneCount = (counts.remediated ?? 0) + (counts.dismissed ?? 0);
  const isPending = tab === "pending";
  const filtered = isPending
    ? searchMatched.filter((g) => (g.status || "open") === "open")
    : searchMatched.filter((g) => g.status === "remediated" || g.status === "dismissed");
  const allSel = filtered.length > 0 && filtered.every((g) => selected.has(g.accountMasked));
  const allExp = filtered.length > 0 && filtered.every((g) => expanded.has(g.accountMasked));
  const toggleSel = (a: string) => setSelected((s) => { const n = new Set(s); if (n.has(a)) n.delete(a); else n.add(a); return n; });
  const toggleExp = (a: string) => setExpanded((s) => { const n = new Set(s); if (n.has(a)) n.delete(a); else n.add(a); return n; });

  // 화면에 보이는(filtered) 선택만 일괄대상 — 검색/필터로 가려진 계정엔 적용 안 함
  const visibleSel = filtered.filter((g) => selected.has(g.accountMasked));

  async function bulkApply(status: string) {
    const targets = filtered.filter((g) => selected.has(g.accountMasked));
    if (!targets.length) return;
    setBulkBusy(status); setBulkErr("");
    const fails: string[] = [];
    let ok = 0;
    try {
      // 기존 메모(note)는 보존하며 상태만 변경 (일괄 시 메모 유실 방지)
      for (const g of targets) {
        const { error } = await supabase.rpc("set_remediation", { p_account: g.accountMasked, p_status: status, p_note: g.note ?? null });
        if (error) fails.push(g.accountMasked);
        else ok++;
      }
    } finally {
      setSelected(new Set());
      onChanged();
      setBulkBusy("");
      setBulkErr(fails.length ? `${ok}건 처리 · ${fails.length}건 실패` : "");
    }
  }

  if (!findings.length) return <p className="px-5 py-10 text-center text-muted">노출된 계정이 없습니다. 👍</p>;

  return (
    <div className="p-4">
      <div className="sticky top-0 z-20 -mx-4 mb-2 border-b border-slate-100 bg-white/95 px-4 pb-2.5 pt-1 backdrop-blur">
        <div className="flex flex-wrap items-center gap-2">
          <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="계정·도메인 검색" className="w-40 rounded-lg border border-slate-300 px-2.5 py-1.5 text-sm outline-none focus:border-sky-400" />
          <div className="inline-flex gap-1">
            <button onClick={() => { setTab("pending"); setSelected(new Set()); }} className={`rounded-full border px-3 py-1 text-xs font-semibold ${isPending ? "border-rose-300 bg-rose-100 text-rose-800" : "border-slate-200 bg-white text-slate-500 hover:bg-slate-50"}`}>조치 필요 {pendingCount}</button>
            <button onClick={() => { setTab("done"); setSelected(new Set()); }} className={`rounded-full border px-3 py-1 text-xs font-semibold ${!isPending ? "border-teal-300 bg-teal-100 text-teal-800" : "border-slate-200 bg-white text-slate-500 hover:bg-slate-50"}`}>조치 완료 {doneCount}</button>
          </div>
          <span className="ml-auto inline-flex items-center gap-1.5">
            <button onClick={() => setSelected(allSel ? new Set() : new Set(filtered.map((g) => g.accountMasked)))} className="rounded-lg border border-slate-300 px-2.5 py-1 text-xs font-medium text-slate-600 hover:bg-slate-50">{allSel ? "선택해제" : "전체선택"}</button>
            <button onClick={() => setExpanded(allExp ? new Set() : new Set(filtered.map((g) => g.accountMasked)))} className="rounded-lg border border-slate-300 px-2.5 py-1 text-xs font-medium text-slate-600 hover:bg-slate-50">{allExp ? "전체접기" : "전체펼치기"}</button>
          </span>
        </div>
        {visibleSel.length > 0 && (
          <div className="mt-2 flex flex-wrap items-center gap-2 rounded-lg border border-sky-200 bg-sky-50 px-3 py-2">
            <span className="text-xs font-semibold text-sky-800">{visibleSel.length}개 선택 — 일괄조치:</span>
            <button onClick={() => bulkApply("remediated")} disabled={!!bulkBusy} className="rounded-lg bg-teal-600 px-2.5 py-1 text-xs font-bold text-white hover:bg-teal-700 disabled:opacity-50">{bulkBusy === "remediated" ? "저장…" : "조치완료"}</button>
            <button onClick={() => bulkApply("dismissed")} disabled={!!bulkBusy} className="rounded-lg bg-sky-600 px-2.5 py-1 text-xs font-bold text-white hover:bg-sky-700 disabled:opacity-50">{bulkBusy === "dismissed" ? "저장…" : "이상없음"}</button>
            <button onClick={() => bulkApply("open")} disabled={!!bulkBusy} className="rounded-lg border border-slate-300 bg-white px-2.5 py-1 text-xs font-semibold text-slate-600 hover:bg-slate-100 disabled:opacity-50">{bulkBusy === "open" ? "저장…" : "미조치"}</button>
            <button onClick={() => setSelected(new Set())} className="text-xs font-medium text-slate-500 hover:underline">해제</button>
            {bulkErr && <span className="text-[11px] font-semibold text-rose-600">{bulkErr}</span>}
          </div>
        )}
      </div>

      <div className="space-y-2">
        {filtered.map((g) => {
          const sev = SEVERITY_META[g.severity];
          const st = STATUS_META[g.status] ?? STATUS_META.open;
          const isOpen = expanded.has(g.accountMasked);
          const isSel = selected.has(g.accountMasked);
          return (
            <div key={g.accountMasked} className={`overflow-hidden rounded-xl border bg-white ${isSel ? "border-sky-400 ring-1 ring-sky-200" : g.hasStealer ? "border-rose-300" : "border-slate-200"}`}>
              <div className={`flex items-center gap-2 px-3 py-2 ${g.hasStealer && isPending ? "bg-rose-50" : "bg-slate-50"}`}>
                <input type="checkbox" checked={isSel} onChange={() => toggleSel(g.accountMasked)} className="h-4 w-4 shrink-0 cursor-pointer accent-sky-600" aria-label="계정 선택" />
                <button onClick={() => toggleExp(g.accountMasked)} className="inline-flex min-w-0 flex-1 items-center gap-1.5 text-left">
                  <span className="shrink-0 text-xs text-slate-400">{isOpen ? "▾" : "▸"}</span>
                  <span className="inline-flex min-w-0 flex-wrap items-center gap-1.5 break-all font-mono text-sm font-semibold text-ink">
                    {g.hasStealer && <span className="rounded-full bg-rose-600 px-1.5 py-0.5 text-[10px] font-bold text-white" title="유출+인포스틸러 동시 — 최우선">🔴</span>}
                    {g.isNew && <span className="rounded-full bg-amber-100 px-1.5 py-0.5 text-[10px] font-bold text-amber-700">NEW</span>}
                    <AcctLabel accountMasked={g.accountMasked} domain={g.domain} />
                  </span>
                </button>
                <span className="inline-flex shrink-0 items-center gap-1.5">
                  {!isPending && g.note && <span className="hidden max-w-[180px] truncate text-[11px] text-muted md:inline" title={g.note}>📝 {g.note}</span>}
                  <span className={`rounded-full border px-2 py-0.5 text-[11px] font-semibold ${st.cls}`}>{st.label}</span>
                  <span className={`hidden items-center rounded-full border px-2 py-0.5 text-xs font-semibold sm:inline-flex ${sev.chip}`}>{sev.label}</span>
                  <span className="text-[11px] text-muted">{g.exposures.length}건</span>
                </span>
              </div>
              {isOpen && (
                <>
                  <ul>
                    {g.exposures.map((e) => (
                      <li key={e.id} className="flex flex-wrap items-center gap-x-3 gap-y-1 border-t border-slate-50 px-4 py-2 text-sm">
                        <span className="min-w-0 break-words font-medium text-slate-700">{e.title}</span>
                        <span className="shrink-0 font-mono text-xs text-muted">{e.date || "—"}</span>
                        <span className="flex flex-wrap gap-1">
                          {e.dataClasses.slice(0, 4).map((dc) => (<span key={dc} className="rounded border border-slate-200 bg-slate-50 px-1.5 py-0.5 text-[11px] text-slate-600">{dc}</span>))}
                        </span>
                        <span className="ml-auto shrink-0 text-[11px] text-muted">{e.source}{e.referenceUrl && <a href={e.referenceUrl} target="_blank" rel="noreferrer" className="ml-1.5 font-semibold text-sky-600 hover:underline">↗</a>}</span>
                      </li>
                    ))}
                  </ul>
                  <RemediationControls account={g.accountMasked} status={g.status} note={g.note} by={g.by} at={g.at} suggestion={suggestAction(g.hasStealer, new Set(g.exposures.flatMap((e) => e.dataClasses)))} onChanged={onChanged} />
                </>
              )}
            </div>
          );
        })}
        {filtered.length === 0 && <p className="py-8 text-center text-sm text-muted">{isPending ? (query ? "조건에 맞는 미조치 계정이 없습니다." : "조치 필요 계정이 없습니다. 모두 처리됨 👍") : "아직 조치한 계정이 없습니다."}</p>}
      </div>
    </div>
  );
}

function fmtDate(iso: string) {
  if (!iso) return "—";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleDateString("ko-KR", { year: "numeric", month: "2-digit", day: "2-digit" });
}

// ── 관제(SOC) 내보내기 — 인포스틸러 점검내역을 CSV/JSON 파일로 다운로드(외부 전송 없음, 로컬 다운로드) ──
function downloadFile(name: string, mime: string, content: string) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = name;
  document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1500);
}
function csvCell(v: unknown) {
  const s = v == null ? "" : String(v);
  const needsQuote = s.indexOf('"') >= 0 || s.indexOf(",") >= 0 || s.indexOf("\n") >= 0 || s.indexOf("\r") >= 0;
  return needsQuote ? '"' + s.split('"').join('""') + '"' : s;
}
function tsStamp() {
  return new Date().toISOString().slice(0, 16).split("-").join("").split(":").join("").split("T").join("");
}
function exportInfostealerCsv(items: InfostealerFinding[], hosts: InfostealerHost[]) {
  const head = ["계열사", "도메인", "총감염", "임직원", "사용자", "서드파티", "최초탐지", "최근점검", "탈취로그인URL", "URL유형", "노출횟수"];
  const rows: string[][] = [];
  for (const i of items) {
    const inst = INSTITUTIONS[i.domain] ?? i.domain;
    const fs = i.firstSeenAt ? fmtDate(i.firstSeenAt) : "";
    const ls = i.scannedAt ? fmtDate(i.scannedAt) : "";
    const base = [inst, i.domain, String(i.total), String(i.employees), String(i.users), String(i.thirdParties), fs, ls];
    if (!i.affectedUrls.length) rows.push([...base, "", "", ""]);
    else for (const u of i.affectedUrls) rows.push([...base, u.url, u.type, String(u.occurrence)]);
  }
  let csv = [head, ...rows].map((r) => r.map(csvCell).join(",")).join("\r\n");
  if (hosts.length) {
    const hh = ["계정", "도메인", "감염일", "최초탐지", "스틸러", "PC", "OS", "IP", "사내서비스", "개인서비스", "악성코드경로"];
    const hr = hosts.map((h) => [h.accountMasked, h.domain, h.dateCompromised ?? "", h.firstSeenAt ? fmtDate(h.firstSeenAt) : "", h.stealerFamily ?? "", h.computerName ?? "", h.operatingSystem ?? "", h.ip ?? "", String(h.totalCorporateServices), String(h.totalUserServices), h.malwarePath ?? ""]);
    csv += "\r\n\r\n=== 감염 호스트 상세 ===\r\n" + [hh, ...hr].map((r) => r.map(csvCell).join(",")).join("\r\n");
  }
  downloadFile(`infostealer_inspection_${tsStamp()}.csv`, "text/csv;charset=utf-8", String.fromCharCode(0xfeff) + csv);
}
function exportInfostealerJson(items: InfostealerFinding[], hosts: InfostealerHost[]) {
  const payload = {
    generatedAt: new Date().toISOString(),
    source: "JB금융 다크웹 인포스틸러 모니터링",
    note: "관제(SOC) 대응용. 계정은 마스킹·비밀번호/IP는 부분 마스킹 값만 포함(평문 없음).",
    domains: items.map((i) => ({ institution: INSTITUTIONS[i.domain] ?? i.domain, ...i })),
    hosts,
  };
  downloadFile(`infostealer_inspection_${tsStamp()}.json`, "application/json;charset=utf-8", JSON.stringify(payload, null, 2));
}

// Supabase 3개 테이블 → BreachScan 조립 (관리자 인증 후 클라이언트에서).
async function fetchScan(): Promise<BreachScan> {
  const [bf, sr, inf, hosts] = await Promise.all([
    supabase
      .from("breach_findings")
      .select(
        "finding_id,account_masked,account,domain,breach_name,breach_title,breach_date,data_classes,severity,is_new,discovered_at,source,reference_url,status,remediation_note,remediated_by,remediated_at"
      ),
    supabase.from("scan_runs").select("*").order("scanned_at", { ascending: false }).limit(30),
    supabase.from("infostealer_findings").select("*").order("total", { ascending: false }),
    supabase.from("infostealer_hosts").select("*").order("date_compromised", { ascending: false }),
  ]);
  if (bf.error) throw bf.error;
  if (sr.error) throw sr.error;
  if (inf.error) throw inf.error;
  // infostealer_hosts: 테이블 미생성/권한 오류 시 빈 배열(대시보드 중단 방지)

  const findings = (bf.data ?? []).map((r) => ({
    id: r.finding_id,
    // 관리자 인증 뒤: 식별(full) 우선, 없으면 마스킹.
    accountMasked: r.account || r.account_masked,
    domain: r.domain,
    breachName: r.breach_name,
    breachTitle: r.breach_title ?? r.breach_name,
    breachDate: r.breach_date ?? "",
    dataClasses: r.data_classes ?? [],
    severity: r.severity as BreachSeverity,
    isNew: !!r.is_new,
    discoveredAt: r.discovered_at,
    source: r.source ?? "",
    referenceUrl: r.reference_url ?? undefined,
    status: r.status ?? "open",
    remediationNote: r.remediation_note ?? "",
    remediatedBy: r.remediated_by ?? "",
    remediatedAt: r.remediated_at ?? "",
  }));
  findings.sort((a, b) => {
    if (a.isNew !== b.isNew) return a.isNew ? -1 : 1;
    if (SEVERITY_RANK[b.severity] !== SEVERITY_RANK[a.severity])
      return SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity];
    return (b.breachDate || "").localeCompare(a.breachDate || "");
  });

  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0 } as Record<BreachSeverity, number>;
  const byDomainMap = new Map<string, number>();
  let newCount = 0;
  for (const f of findings) {
    bySeverity[f.severity] = (bySeverity[f.severity] ?? 0) + 1;
    byDomainMap.set(f.domain, (byDomainMap.get(f.domain) ?? 0) + 1);
    if (f.isNew) newCount++;
  }
  const latest = (sr.data ?? [])[0];
  const domains: string[] = latest?.domains?.length ? latest.domains : [...byDomainMap.keys()];

  return {
    generatedAt: latest?.scanned_at ?? new Date().toISOString(),
    source: latest?.source ?? "Supabase",
    status: latest?.status ?? "ok",
    isDemo: false,
    domains,
    findings,
    summary: {
      total: findings.length,
      newCount,
      bySeverity,
      byDomain: [...byDomainMap.entries()].map(([domain, count]) => ({ domain, count })),
    },
    history: [...(sr.data ?? [])]
      .reverse()
      .map((r) => ({ scannedAt: r.scanned_at, total: r.total, newCount: r.new_count })),
    note: latest?.note ?? undefined,
    infostealer: (inf.data ?? []).map((i) => ({
      domain: i.domain,
      source: i.source,
      total: i.total,
      employees: i.employees,
      users: i.users,
      thirdParties: i.third_parties,
      affectedUrls: i.affected_urls ?? [],
      firstSeenAt: i.first_seen_at ?? undefined,
      scannedAt: i.scanned_at,
    })),
    infostealerHosts: (hosts.error ? [] : hosts.data ?? []).map((h) => ({
      accountMasked: h.account_masked,
      domain: h.domain,
      computerName: h.computer_name ?? null,
      operatingSystem: h.operating_system ?? null,
      ip: h.ip ?? null,
      dateCompromised: h.date_compromised ?? null,
      stealerFamily: h.stealer_family ?? null,
      malwarePath: h.malware_path ?? null,
      antiviruses: h.antiviruses ?? [],
      totalCorporateServices: h.total_corporate_services ?? 0,
      totalUserServices: h.total_user_services ?? 0,
      topPasswords: h.top_passwords ?? [],
      topLogins: h.top_logins ?? [],
      firstSeenAt: h.first_seen_at ?? undefined,
      scannedAt: h.scanned_at,
    })),
    sources: latest?.sources ?? [],
  };
}

function LoginGate({ onSignedIn }: { onSignedIn: () => void }) {
  // 고정 관리자 이메일이 설정돼 있으면 비밀번호만 받는다.
  // 미설정(또는 "다른 계정") 일 때만 이메일 입력을 노출.
  const hasFixedEmail = Boolean(adminEmail);
  const [email, setEmail] = useState(adminEmail);
  const [showEmail, setShowEmail] = useState(!hasFixedEmail);
  const [pw, setPw] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    const loginEmail = (showEmail ? email : adminEmail).trim();
    if (!loginEmail) {
      setErr("관리자 이메일이 설정되지 않았습니다. ‘다른 계정으로 로그인’으로 이메일을 입력하세요.");
      setShowEmail(true);
      return;
    }
    setBusy(true);
    setErr("");
    const { error } = await supabase.auth.signInWithPassword({ email: loginEmail, password: pw });
    setBusy(false);
    if (error) setErr(showEmail ? "로그인 실패: 이메일/비밀번호를 확인하세요." : "로그인 실패: 비밀번호를 확인하세요.");
    else onSignedIn();
  }

  return (
    <div className="flex min-h-[70vh] items-center justify-center px-4">
      <form onSubmit={submit} className="w-full max-w-sm rounded-2xl border border-slate-200 bg-white p-7 shadow-xl">
        <div className="mb-5 flex items-center gap-2">
          <span className="flex h-10 w-10 items-center justify-center rounded-xl bg-cyan-600 text-white">
            <Lock size={18} aria-hidden />
          </span>
          <div>
            <h1 className="text-lg font-bold text-ink">관리자 로그인</h1>
            <p className="text-xs text-muted">다크웹 유출 모니터링 · 내부 전용</p>
          </div>
        </div>

        {/* 이메일: 고정 계정이면 숨기고, 어떤 계정으로 들어가는지 칩으로 안내 */}
        {showEmail ? (
          <>
            <label className="mb-1 block text-xs font-semibold text-muted">이메일</label>
            <input
              type="email"
              autoComplete="username"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="mb-3 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-rose-400"
            />
          </>
        ) : (
          <div className="mb-3 flex items-center gap-2 rounded-lg border border-slate-200 bg-slate-50 px-3 py-2 text-xs text-slate-600">
            <Lock size={12} className="shrink-0 text-slate-400" aria-hidden />
            <span className="font-mono">{adminEmail}</span>
            <span className="ml-auto text-[11px] text-muted">관리자 계정</span>
          </div>
        )}

        <label className="mb-1 block text-xs font-semibold text-muted">비밀번호</label>
        <input
          type="password"
          autoComplete="current-password"
          required
          autoFocus
          value={pw}
          onChange={(e) => setPw(e.target.value)}
          className="mb-4 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-rose-400"
        />
        {err && <p className="mb-3 text-xs font-semibold text-rose-600">{err}</p>}
        <button
          type="submit"
          disabled={busy}
          className="w-full rounded-lg bg-cyan-700 py-2.5 text-sm font-bold text-white transition hover:bg-cyan-600 disabled:opacity-60"
        >
          {busy ? "확인 중…" : "로그인"}
        </button>

        {hasFixedEmail && (
          <button
            type="button"
            onClick={() => {
              setShowEmail((v) => !v);
              setErr("");
              if (showEmail) setEmail(adminEmail); // 고정 계정으로 되돌릴 때 값 복원
            }}
            className="mt-3 block w-full text-center text-[11px] font-semibold text-slate-500 underline-offset-2 hover:text-slate-700 hover:underline"
          >
            {showEmail ? "고정 관리자 계정으로 로그인" : "다른 계정으로 로그인"}
          </button>
        )}

        <p className="mt-4 text-center text-[11px] leading-5 text-muted">
          승인된 관리자만 접근할 수 있습니다. 데이터는 로그인 후에만 조회됩니다(RLS 보호).
        </p>
      </form>
    </div>
  );
}

function SetPasswordPanel({ onDone, onCancel }: { onDone: () => void; onCancel?: () => void }) {
  const [pw, setPw] = useState("");
  const [pw2, setPw2] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setErr("");
    if (pw.length < 6) return setErr("비밀번호는 6자 이상이어야 합니다.");
    if (pw !== pw2) return setErr("두 비밀번호가 일치하지 않습니다.");
    setBusy(true);
    const { error } = await supabase.auth.updateUser({ password: pw });
    setBusy(false);
    if (error) setErr("설정 실패: " + error.message);
    else {
      // 설정 후 URL의 토큰 흔적 제거
      if (typeof window !== "undefined") window.history.replaceState({}, "", window.location.pathname);
      onDone();
    }
  }

  return (
    <div className="flex min-h-[70vh] items-center justify-center px-4">
      <form onSubmit={submit} className="w-full max-w-sm rounded-2xl border border-slate-200 bg-white p-7 shadow-xl">
        <div className="mb-5 flex items-center gap-2">
          <span className="flex h-10 w-10 items-center justify-center rounded-xl bg-cyan-600 text-white"><Lock size={18} aria-hidden /></span>
          <div>
            <h1 className="text-lg font-bold text-ink">비밀번호 설정</h1>
            <p className="text-xs text-muted">관리자 계정의 새 비밀번호를 입력하세요</p>
          </div>
        </div>
        <label className="mb-1 block text-xs font-semibold text-muted">새 비밀번호</label>
        <input type="password" autoComplete="new-password" required value={pw} onChange={(e) => setPw(e.target.value)} className="mb-3 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-rose-400" />
        <label className="mb-1 block text-xs font-semibold text-muted">새 비밀번호 확인</label>
        <input type="password" autoComplete="new-password" required value={pw2} onChange={(e) => setPw2(e.target.value)} className="mb-4 w-full rounded-lg border border-slate-300 px-3 py-2 text-sm outline-none focus:border-rose-400" />
        {err && <p className="mb-3 text-xs font-semibold text-rose-600">{err}</p>}
        <button type="submit" disabled={busy} className="w-full rounded-lg bg-cyan-700 py-2.5 text-sm font-bold text-white transition hover:bg-cyan-600 disabled:opacity-60">{busy ? "설정 중…" : "비밀번호 설정"}</button>
        {onCancel && <button type="button" onClick={onCancel} className="mt-2 w-full rounded-lg border border-slate-300 py-2 text-sm font-semibold text-slate-600 hover:bg-slate-50">취소</button>}
      </form>
    </div>
  );
}

// 조치 내역(감사 로그) — remediation_log.
function RemediationLogPanel({ reloadKey }: { reloadKey: string }) {
  const [rows, setRows] = useState<Array<{ id: number; account_masked: string; status: string; note: string; actor: string; created_at: string }>>([]);
  const [err, setErr] = useState("");
  useEffect(() => {
    supabase
      .from("remediation_log")
      .select("id,account_masked,status,note,actor,created_at")
      .order("created_at", { ascending: false })
      .limit(50)
      .then(({ data, error }) => {
        if (error) setErr(error.message);
        else setRows((data ?? []) as typeof rows);
      });
  }, [reloadKey]);
  return (
    <Panel title="조치 변경 이력" subtitle="모든 상태 변경·메모 기록 (감사 로그 · 수정 불가)">
      {err ? (
        <p className="py-4 text-center text-sm text-rose-600">로그 조회 실패: {err}</p>
      ) : rows.length === 0 ? (
        <p className="py-6 text-center text-sm text-muted">조치 이력이 없습니다.</p>
      ) : (
        <>
          {/* 데스크톱: 테이블 */}
          <div className="hidden overflow-x-auto sm:block">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-slate-200 text-left text-xs font-semibold uppercase tracking-wide text-muted">
                  <th className="px-3 py-2">시각</th><th className="px-3 py-2">계정</th><th className="px-3 py-2">상태</th><th className="px-3 py-2">메모</th><th className="px-3 py-2">담당</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r) => {
                  const s = STATUS_META[r.status] ?? STATUS_META.open;
                  return (
                    <tr key={r.id} className="border-b border-slate-100 align-top last:border-0">
                      <td className="whitespace-nowrap px-3 py-2 font-mono text-[11px] text-muted">{fmtDate(r.created_at)}</td>
                      <td className="break-all px-3 py-2 font-mono text-xs text-ink">{r.account_masked}</td>
                      <td className="px-3 py-2"><span className={`rounded-full border px-2 py-0.5 text-[11px] font-semibold ${s.cls}`}>{s.label}</span></td>
                      <td className="px-3 py-2 text-slate-700">{r.note || "—"}</td>
                      <td className="px-3 py-2 text-[11px] text-muted">{r.actor}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
          {/* 모바일: 카드 */}
          <ul className="space-y-2 sm:hidden">
            {rows.map((r) => {
              const s = STATUS_META[r.status] ?? STATUS_META.open;
              return (
                <li key={r.id} className="rounded-lg border border-slate-200 bg-slate-50 p-3">
                  <div className="flex items-center justify-between gap-2">
                    <span className="min-w-0 break-all font-mono text-xs text-ink">{r.account_masked}</span>
                    <span className={`shrink-0 rounded-full border px-2 py-0.5 text-[11px] font-semibold ${s.cls}`}>{s.label}</span>
                  </div>
                  {r.note && <p className="mt-1 text-[12px] leading-5 text-slate-700">{r.note}</p>}
                  <div className="mt-1 flex flex-wrap items-center gap-x-2 text-[11px] text-muted">
                    <span className="font-mono">{fmtDate(r.created_at)}</span><span aria-hidden>·</span><span className="break-all">{r.actor}</span>
                  </div>
                </li>
              );
            })}
          </ul>
        </>
      )}
    </Panel>
  );
}

export default function DashboardClient() {
  const [session, setSession] = useState<Session | null>(null);
  const [ready, setReady] = useState(false);
  const [scan, setScan] = useState<BreachScan | null>(null);
  const [loadErr, setLoadErr] = useState("");
  const [mustSetPw, setMustSetPw] = useState(false); // 초대/재설정 링크로 진입 → 비번 설정 필요
  const [showSetPw, setShowSetPw] = useState(false); // 로그인 상태에서 수동 변경

  useEffect(() => {
    if (!supabaseConfigured) {
      setReady(true);
      return;
    }
    // 초대/재설정 메일 링크는 URL에 type=recovery|invite 를 담아 온다.
    const hash = typeof window !== "undefined" ? window.location.hash + window.location.search : "";
    if (/type=(recovery|invite)/.test(hash)) setMustSetPw(true);

    supabase.auth.getSession().then(({ data }) => {
      setSession(data.session);
      setReady(true);
    });
    const { data: sub } = supabase.auth.onAuthStateChange((event, s) => {
      setSession(s);
      if (event === "PASSWORD_RECOVERY") setMustSetPw(true);
    });
    return () => sub.subscription.unsubscribe();
  }, []);

  const load = useCallback(() => {
    setLoadErr("");
    fetchScan()
      .then(setScan)
      .catch((e) => setLoadErr(e?.message ?? "데이터 조회 실패"));
  }, []);

  useEffect(() => {
    if (session) load();
    else setScan(null);
  }, [session, load]);

  if (!supabaseConfigured)
    return (
      <p className="px-4 py-20 text-center text-sm text-muted">
        Supabase 환경변수(NEXT_PUBLIC_SUPABASE_URL / ANON_KEY)가 설정되지 않았습니다.
      </p>
    );
  if (!ready) return <p className="px-4 py-20 text-center text-sm text-muted">로딩 중…</p>;
  if (!session) return <LoginGate onSignedIn={load} />;
  if (mustSetPw || showSetPw)
    return (
      <SetPasswordPanel
        onDone={() => {
          setMustSetPw(false);
          setShowSetPw(false);
          load();
        }}
        onCancel={showSetPw && !mustSetPw ? () => setShowSetPw(false) : undefined}
      />
    );
  if (loadErr)
    return <p className="px-4 py-20 text-center text-sm text-rose-600">데이터 조회 실패: {loadErr}</p>;
  if (!scan) return <p className="px-4 py-20 text-center text-sm text-muted">데이터 불러오는 중…</p>;

  const { summary } = scan;
  // 계정 단위 조치 현황 — 상단 KPI 동기화(유출 계정 상세 탭과 동일 규칙: 그룹 status = 비-open finding 우선).
  const acctStatus = new Map<string, string>();
  for (const f of scan.findings) {
    if (f.status && f.status !== "open") acctStatus.set(f.accountMasked, f.status);
    else if (!acctStatus.has(f.accountMasked)) acctStatus.set(f.accountMasked, "open");
  }
  const acctTotal = acctStatus.size;
  let acctOpen = 0;
  for (const st of acctStatus.values()) if (st === "open") acctOpen++;
  const acctDone = acctTotal - acctOpen;
  // 도메인·심각도 조치현황 집계 (계정 단위 — 개요/차트 동기화)
  const acctDomain = new Map<string, string>();
  for (const f of scan.findings) if (!acctDomain.has(f.accountMasked)) acctDomain.set(f.accountMasked, f.domain);
  const domainRemed = new Map<string, { open: number; done: number }>();
  for (const [acct, st] of acctStatus) {
    const d = acctDomain.get(acct) ?? "";
    const e = domainRemed.get(d) ?? { open: 0, done: 0 };
    if (st === "open") e.open++; else e.done++;
    domainRemed.set(d, e);
  }
  const openSev: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const f of scan.findings) if (acctStatus.get(f.accountMasked) === "open") openSev[f.severity] = (openSev[f.severity] ?? 0) + 1;
  // 심각도 분포·도메인별 노출 = '조치 필요(미조치)' 기준 → 조치하면 줄어든다(동기화)
  const severityItems = (Object.keys(SEVERITY_META) as BreachSeverity[])
    .map((sev) => ({ label: SEVERITY_META[sev].label, value: openSev[sev] ?? 0, color: SEVERITY_META[sev].color, display: String(openSev[sev] ?? 0) }))
    .filter((it) => it.value > 0);
  const domainItems = [...domainRemed.entries()]
    .map(([domain, r]) => ({ label: domain, value: r.open, display: `${r.open}계정` }))
    .filter((it) => it.value > 0)
    .sort((a, b) => b.value - a.value);
  const historyRecent = [...scan.history].slice(-12).reverse();
  const infostealer = scan.infostealer ?? [];
  const infoTotal = infostealer.reduce((s, i) => s + i.total, 0);
  const infoItems = infostealer
    .map((i) => ({ label: i.domain, value: i.total, display: `${i.total}건` }))
    .filter((it) => it.value > 0)
    .sort((a, b) => b.value - a.value);
  const sources = scan.sources ?? [];
  const hosts = scan.infostealerHosts ?? [];
  const hostsCorpTotal = hosts.reduce((s, h) => s + (h.totalCorporateServices || 0), 0);

  // 계열사별 통합 개요 (유출 계정 + 인포스틸러)
  const breachByDomain = new Map(summary.byDomain.map((d) => [d.domain, d.count]));
  const infoByDomain = new Map(infostealer.map((i) => [i.domain, i]));
  const overview = scan.domains
    .map((d) => {
      const inf = infoByDomain.get(d);
      const rem = domainRemed.get(d) ?? { open: 0, done: 0 };
      return {
        domain: d,
        name: INSTITUTIONS[d] ?? d,
        breach: breachByDomain.get(d) ?? 0,
        acctOpen: rem.open,
        acctDone: rem.done,
        acctTotal: rem.open + rem.done,
        infoTotal: inf?.total ?? 0,
        employees: inf?.employees ?? 0,
        users: inf?.users ?? 0,
        thirdParties: inf?.thirdParties ?? 0,
      };
    })
    .sort((a, b) => b.breach + b.infoTotal - (a.breach + a.infoTotal));

  // 인포스틸러 감염 유형 집계 (대응 우선순위 판단용)
  const infoEmp = infostealer.reduce((s, i) => s + (i.employees || 0), 0);
  const infoUsr = infostealer.reduce((s, i) => s + (i.users || 0), 0);
  const info3p = infostealer.reduce((s, i) => s + (i.thirdParties || 0), 0);

  return (
    <div className="space-y-7 overflow-x-clip pb-14">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="inline-flex items-center gap-1.5 rounded-full border border-rose-300 bg-rose-50 px-3 py-1 text-xs font-bold text-rose-700">
          <Lock size={12} className="shrink-0" aria-hidden /> 관리자 전용 · 외부 공유 금지
        </span>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowSetPw(true)}
            className="inline-flex items-center gap-1.5 rounded-full border border-slate-300 px-3 py-1 text-xs font-semibold text-slate-600 hover:bg-slate-50"
          >
            <Lock size={12} aria-hidden /> 비밀번호 변경
          </button>
          <button
            onClick={() => supabase.auth.signOut()}
            className="inline-flex items-center gap-1.5 rounded-full border border-slate-300 px-3 py-1 text-xs font-semibold text-slate-600 hover:bg-slate-50"
          >
            <LogOut size={12} aria-hidden /> 로그아웃
          </button>
        </div>
      </div>

      {/* 스캔 상태 배너 — 자정 배치 성공/실패·지연을 상단에서 즉시 인지 */}
      {(() => {
        const ageH = (Date.now() - new Date(scan.generatedAt).getTime()) / 3600000;
        const stale = !Number.isNaN(ageH) && ageH > 26;
        const ok = scan.status === "ok" && !stale;
        if (ok) {
          return (
            <div className="flex flex-wrap items-center gap-x-2 gap-y-1 rounded-xl border border-teal-200 bg-teal-50 px-4 py-2 text-xs text-teal-800">
              <ShieldCheck size={14} className="shrink-0" aria-hidden />
              <span className="font-bold">스캔 정상</span>
              <span className="text-teal-700">최근 스캔 {fmtDate(scan.generatedAt)} · 수집 출처 {sources.length}종{summary.newCount > 0 ? ` · 신규 ${summary.newCount}건` : ""}</span>
            </div>
          );
        }
        return (
          <div className="flex flex-wrap items-center gap-x-2 gap-y-1 rounded-xl border border-rose-300 bg-rose-50 px-4 py-2.5 text-xs text-rose-800">
            <AlertTriangle size={15} className="shrink-0" aria-hidden />
            <span className="font-bold">{stale ? "스캔 지연" : "스캔 이상"}</span>
            <span className="text-rose-700">
              {stale ? `최근 스캔이 약 ${Math.floor(ageH)}시간 전입니다 — 자정 배치가 멈췄을 수 있어 점검이 필요합니다.` : `상태: ${scan.status}`}
              {scan.note ? ` · ${scan.note}` : ""}
            </span>
          </div>
        );
      })()}

      <PageHero
        kicker="보안 · 다크웹 유출 모니터링 (관리자)"
        title="회사 계정 유출 모니터링"
        description="매일 자정 유출 인텔리전스 API를 조회해 회사 계정 노출을 추적합니다. 관리자 인증 후 식별 데이터를 표시합니다."
        right={
          <span className="inline-flex items-center gap-1.5 rounded-full border border-white/20 bg-white/10 px-3 py-1.5 text-xs font-semibold text-white">
            <CalendarClock size={13} aria-hidden /> 최근 스캔 {fmtDate(scan.generatedAt)}
          </span>
        }
      />

      <div className="stat-grid">
        <StatTile label="모니터링 도메인" value={scan.domains.length} unit="개" icon={<Globe size={18} />} accent="#3157a4" sub={scan.domains.join(", ") || "미설정"} />
        <StatTile label="유출 노출 계정" value={acctTotal} unit="계정" icon={<ShieldAlert size={18} />} accent="#be123c" trend={{ label: acctOpen > 0 ? `조치 필요 ${acctOpen}` : "모두 조치됨", dir: acctOpen > 0 ? "down" : "up" }} sub={`조치완료 ${acctDone} · 노출 ${summary.total}건`} />
        <StatTile label="이번 스캔 신규" value={summary.newCount} unit="건" icon={<Sparkles size={18} />} accent="#b45309" trend={{ label: summary.newCount > 0 ? "신규 발견" : "변동 없음", dir: summary.newCount > 0 ? "down" : "neutral" }} sub="직전 대비" />
        <StatTile label="인포스틸러 감염" value={infoTotal} unit="건" icon={<Bug size={18} />} accent="#7f1d1d" trend={{ label: "도메인 전수", dir: infoTotal > 0 ? "down" : "up" }} sub="Cavalier" />
      </div>

      <Panel title="계열사별 위험 개요" subtitle="회사별 유출 계정 · 인포스틸러 감염 통합 현황" right={<span className="chip chip-neutral"><Globe size={13} className="mr-1 inline" aria-hidden /> {overview.length}개사</span>}>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {overview.map((o) => {
            const dot = o.acctOpen > 0 ? "bg-rose-500" : o.infoTotal > 100 ? "bg-rose-400" : o.infoTotal > 0 ? "bg-amber-500" : "bg-teal-500";
            const risk = o.acctOpen > 0 || o.infoTotal > 0;
            return (
              <div key={o.domain} className={`rounded-xl border p-4 ${risk ? "border-rose-200 bg-rose-50/40" : "border-slate-200 bg-slate-50"}`}>
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <div className="truncate text-sm font-bold text-ink">{o.name}</div>
                    <div className="truncate font-mono text-[11px] text-muted">{o.domain}</div>
                  </div>
                  <span className={`mt-1 inline-flex h-2.5 w-2.5 shrink-0 rounded-full ${dot}`} aria-hidden />
                </div>
                <div className="mt-3 grid grid-cols-2 gap-2">
                  <div className="rounded-lg bg-white/70 p-2 text-center">
                    <div className="text-lg font-extrabold text-rose-700">{o.acctTotal}</div>
                    <div className="text-[10px] text-muted">유출 계정</div>
                  </div>
                  <div className="rounded-lg bg-white/70 p-2 text-center">
                    <div className="text-lg font-extrabold text-slate-800">{o.infoTotal.toLocaleString()}</div>
                    <div className="text-[10px] text-muted">인포스틸러</div>
                  </div>
                </div>
                {o.acctTotal > 0 && (
                  <div className="mt-2 flex flex-wrap items-center gap-x-2 gap-y-0.5 text-[10px]">
                    <span className={o.acctOpen > 0 ? "font-semibold text-rose-700" : "text-muted"}>조치 필요 {o.acctOpen}</span>
                    <span className="text-muted">·</span>
                    <span className="text-teal-700">조치 완료 {o.acctDone}</span>
                  </div>
                )}
                {o.infoTotal > 0 && (
                  <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-0.5 text-[10px] text-muted">
                    <span>인포스틸러 — 임직원 {o.employees}</span><span>·</span><span>사용자 {o.users}</span><span>·</span><span>서드파티 {o.thirdParties}</span>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </Panel>

      <section className="grid gap-4 lg:grid-cols-2">
        <Panel title="심각도 분포" subtitle="조치 필요(미조치) 기준 — 데이터 분류 위험도">
          {severityItems.length ? <BarList items={severityItems} unit="건" /> : <p className="py-6 text-center text-sm text-muted">조치 필요 항목 없음 👍</p>}
        </Panel>
        <Panel title="도메인별 노출 (계정 유출)" subtitle="도메인별 조치 필요 계정 수">
          {domainItems.length ? <BarList items={domainItems} /> : <p className="py-6 text-center text-sm text-muted">조치 필요 계정 없음 👍</p>}
        </Panel>
      </section>

      <Panel title="유출 계정 상세 (식별)" subtitle="조치 필요 ↔ 조치 완료 탭으로 관리 — 조치하면 자동으로 '조치 완료'로 이동, 거기서 다시 수정 가능." right={<span className="chip chip-neutral">총 {summary.total}건</span>} bodyClassName="p-0">
        <AccountGroupedFindings findings={scan.findings} onChanged={load} />
      </Panel>

      <RemediationLogPanel reloadKey={scan.findings.map((f) => `${f.id}:${f.status}:${f.remediatedAt}`).join("|")} />

      <Panel title="인포스틸러 점검이란?" subtitle="다크웹 정보탈취 악성코드(인포스틸러) 감염 점검의 개념과 방법">
        <div className="grid gap-4 text-sm leading-6 text-slate-700 lg:grid-cols-2">
          <div className="space-y-2.5">
            <p className="flex gap-2"><Bug size={16} className="mt-0.5 shrink-0 text-rose-600" aria-hidden /><span><strong>인포스틸러</strong>는 감염된 PC에서 브라우저에 저장된 비밀번호·쿠키·세션·자동완성·암호화폐 지갑 등을 통째로 탈취해 다크웹에 유통하는 악성코드입니다. 단순 유출과 달리 <strong>로그인 세션 탈취로 MFA(2단계 인증)까지 우회</strong>될 수 있어 위험합니다.</span></p>
            <p className="flex gap-2"><Database size={16} className="mt-0.5 shrink-0 text-sky-600" aria-hidden /><span>다크웹을 직접 크롤링하지 않고, <strong>Hudson Rock Cavalier</strong>가 합법 수집·정규화한 스틸러 로그(인포스틸러 감염 로그 DB)를 조회합니다.</span></p>
          </div>
          <div className="space-y-2.5">
            <p className="flex gap-2"><ShieldCheck size={16} className="mt-0.5 shrink-0 text-teal-600" aria-hidden /><span><strong>무엇을 점검하나</strong> — ① 회사 4개 도메인 관련 감염 건수(임직원·사용자·서드파티), ② 어떤 로그인 URL이 스틸러 로그에 잡혔는지, ③ 모니터링 계정별 <strong>감염 호스트 상세</strong>(아래).</span></p>
            <p className="flex gap-2"><Lock size={16} className="mt-0.5 shrink-0 text-slate-500" aria-hidden /><span><strong>개인정보</strong> — 계정은 마스킹, 비밀번호·IP는 Hudson Rock이 부분 마스킹한 값만 보관하며 <strong>관리자 인증 후에만</strong> 표시합니다.</span></p>
          </div>
        </div>
        <p className="mt-3 flex gap-2 border-t border-slate-100 pt-3 text-xs text-amber-700"><AlertTriangle size={14} className="mt-0.5 shrink-0" aria-hidden /><span>감염 확인 시: 즉시 비밀번호 재설정 + MFA 재등록 + 해당 단말의 모든 활성 세션 무효화 + 단말 백신 정밀검사/포맷을 권고합니다(세션 쿠키까지 탈취됐을 수 있어 비번 변경만으론 불충분).</span></p>
      </Panel>

      <Panel title="다크웹 인포스틸러 감염 (도메인 전수)" subtitle="악성코드 감염으로 탈취된 다크웹 스틸러 로그. 도메인 전체 집계." right={
        <div className="flex flex-wrap items-center gap-2">
          <span className="chip chip-neutral"><Bug size={13} className="mr-1 inline" aria-hidden /> 총 {infoTotal.toLocaleString()}건</span>
          <button onClick={() => exportInfostealerCsv(infostealer, hosts)} disabled={!infostealer.length} className="inline-flex items-center gap-1 rounded-lg border border-slate-300 px-2.5 py-1 text-xs font-semibold text-slate-600 hover:bg-slate-50 disabled:opacity-50" title="관제(SOC) 이관용 CSV 다운로드"><Download size={12} aria-hidden /> CSV</button>
          <button onClick={() => exportInfostealerJson(infostealer, hosts)} disabled={!infostealer.length} className="inline-flex items-center gap-1 rounded-lg border border-slate-300 px-2.5 py-1 text-xs font-semibold text-slate-600 hover:bg-slate-50 disabled:opacity-50" title="관제(SOC) 이관용 JSON 다운로드"><Download size={12} aria-hidden /> JSON</button>
        </div>
      }>
        {infostealer.length === 0 ? (
          <p className="py-6 text-center text-sm text-muted">인포스틸러 데이터 없음.</p>
        ) : (
          <div className="space-y-5">
            <div className={`rounded-xl border p-4 ${infoEmp > 0 ? "border-rose-300 bg-rose-50" : "border-amber-200 bg-amber-50"}`}>
              <div className="flex items-start gap-2">
                {infoEmp > 0 ? <ShieldAlert size={18} className="mt-0.5 shrink-0 text-rose-600" aria-hidden /> : <Info size={18} className="mt-0.5 shrink-0 text-amber-600" aria-hidden />}
                <div className="text-sm leading-6 text-slate-700">
                  <div className="font-bold text-ink">현재 상황 · 대응 우선순위</div>
                  <p className="mt-0.5">총 <strong>{infoTotal.toLocaleString()}건</strong> — 임직원 단말 <strong className={infoEmp > 0 ? "text-rose-700" : ""}>{infoEmp}</strong> · 고객/사용자 <strong className="text-amber-700">{infoUsr.toLocaleString()}</strong> · 서드파티 {info3p}.</p>
                  <p className="mt-1">
                    {infoEmp > 0
                      ? <><strong className="text-rose-700">사내 단말 감염 발견</strong> — 직원 계정·세션 탈취 위험. 아래 「대응 가이드」의 직원 단말 절차를 즉시 수행하세요.</>
                      : <>사내 단말 침해는 <strong>없으나</strong>, 고객 PC 감염으로 <strong className="text-ink">인터넷뱅킹 로그인 자격증명이 대량 탈취</strong>됐습니다 → 고객 계정 보호·이상거래(FDS) 대응이 우선입니다.</>}
                  </p>
                </div>
              </div>
            </div>
            {infoItems.length > 0 && <BarList items={infoItems} />}
            <div className="grid gap-3 md:grid-cols-2">
              {infostealer.filter((i) => i.total > 0).sort((a, b) => b.total - a.total).map((i) => {
                const seg = [
                  { label: "임직원", v: i.employees, c: "#be123c" },
                  { label: "사용자", v: i.users, c: "#b45309" },
                  { label: "서드파티", v: i.thirdParties, c: "#3157a4" },
                ].filter((s) => s.v > 0);
                const segTotal = seg.reduce((s, x) => s + x.v, 0) || 1;
                return (
                  <div key={i.domain} className="rounded-xl border border-slate-200 bg-slate-50 p-4">
                    <div className="flex items-baseline justify-between gap-2">
                      <div className="min-w-0">
                        <span className="text-sm font-bold text-ink">{INSTITUTIONS[i.domain] ?? i.domain}</span>
                        <span className="ml-1.5 font-mono text-[11px] text-muted">{i.domain}</span>
                      </div>
                      <span className="shrink-0 text-sm font-extrabold text-rose-700">{i.total.toLocaleString()}<span className="text-[11px] font-semibold">건</span></span>
                    </div>
                    {/* 타임라인: 언제 처음 잡혔고 언제 다시 확인됐는지 */}
                    <div className="mt-1 flex flex-wrap items-center gap-x-2 gap-y-0.5 text-[10px] text-muted">
                      <CalendarClock size={10} className="shrink-0 text-slate-400" aria-hidden />
                      <span>최초 탐지 <b className="font-semibold text-slate-600">{i.firstSeenAt ? fmtDate(i.firstSeenAt) : "—"}</b></span>
                      <span aria-hidden>·</span>
                      <span>최근 점검 {fmtDate(i.scannedAt)}</span>
                    </div>
                    {/* 감염 유형 분포 막대 */}
                    <div className="mt-2 flex h-2 overflow-hidden rounded-full bg-slate-200">
                      {seg.map((s) => <div key={s.label} style={{ width: `${(s.v / segTotal) * 100}%`, background: s.c }} aria-hidden />)}
                    </div>
                    <div className="mt-1.5 flex flex-wrap gap-x-3 gap-y-0.5 text-[11px]">
                      <span className="text-rose-700">● 임직원 {i.employees}</span>
                      <span className="text-amber-700">● 사용자 {i.users}</span>
                      <span className="text-sky-700">● 서드파티 {i.thirdParties}</span>
                    </div>
                    {/* 상황 해석 */}
                    <div className="mt-2 rounded-lg bg-white/70 px-2.5 py-1.5 text-[11px] leading-5 text-slate-600">
                      {i.employees > 0
                        ? <span className="font-semibold text-rose-700">⚠ 사내 단말 {i.employees}대 감염 — 직원 계정 탈취 가능, IT보안 즉시 대응</span>
                        : <>고객/외부 단말 감염으로 <strong className="text-slate-800">{INSTITUTIONS[i.domain] ?? i.domain} 로그인 자격증명</strong>이 탈취됨 (사내 단말 0)</>}
                    </div>
                    {i.affectedUrls.length > 0 && (
                      <div className="mt-2 border-t border-slate-200 pt-2">
                        <div className="mb-1 flex items-center gap-1 text-[10px] font-semibold uppercase tracking-wide text-muted">
                          <FileWarning size={11} className="text-amber-500" aria-hidden /> 자격증명이 탈취된 로그인 페이지 · 집중 보호 대상
                        </div>
                        <ul className="space-y-1">
                          {i.affectedUrls.slice(0, 10).map((u) => {
                            const k = urlKind(u.type);
                            return (
                              <li key={u.url} className="flex items-center gap-2 text-[11px]">
                                <span className={`shrink-0 rounded px-1 py-0.5 text-[9px] font-bold ${k.cls}`}>{k.label}</span>
                                <span className="min-w-0 truncate font-mono text-slate-600">{u.url}</span>
                                <span className="ml-auto shrink-0 text-muted">{u.occurrence.toLocaleString()}회</span>
                              </li>
                            );
                          })}
                          {i.affectedUrls.length > 10 && <li className="text-[10px] text-muted">+{i.affectedUrls.length - 10}개 더</li>}
                        </ul>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </Panel>

      <Panel
        title="감염 호스트 상세 (피해 단말)"
        subtitle="모니터링 계정의 인포스틸러 감염 단말 — 민감정보, 관리자 전용·외부 공유 금지"
        right={<span className="chip chip-neutral"><Monitor size={13} className="mr-1 inline" aria-hidden /> {hosts.length}대 · 사내 {hostsCorpTotal}건</span>}
      >
        {hosts.length === 0 ? (
          <div className="py-6 text-center text-sm text-muted">
            <p className="font-semibold text-teal-700">모니터링 계정에서 감염된 호스트가 없습니다. 👍</p>
            <p className="mt-1 text-xs">호스트 상세는 모니터링 대상 계정(<span className="font-mono">MONITORED_EMAILS</span>)에 인포스틸러 감염 이력이 있을 때 자동 표시됩니다.</p>
          </div>
        ) : (
          <div className="space-y-3">
            <p className="flex items-center gap-1.5 rounded-lg border border-rose-200 bg-rose-50 px-3 py-2 text-[11px] font-semibold text-rose-700">
              <Lock size={12} aria-hidden /> 부분 마스킹된 자격증명 샘플이 포함됩니다 — 화면 캡처·외부 공유 금지
            </p>
            {hosts.map((h, idx) => (
              <div key={`${h.accountMasked}-${h.computerName ?? ""}-${idx}`} className="rounded-xl border border-slate-200 bg-slate-50 p-4">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="font-mono text-sm font-bold text-ink">{h.accountMasked}</span>
                  <div className="flex flex-wrap items-center gap-1.5">
                    {h.stealerFamily && (
                      <span className="inline-flex items-center gap-1 rounded-full border border-rose-300 bg-rose-100 px-2 py-0.5 text-[11px] font-semibold text-rose-700">
                        <Bug size={11} aria-hidden /> {h.stealerFamily}
                      </span>
                    )}
                    {h.dateCompromised && (
                      <span className="inline-flex items-center gap-1 text-[11px] text-muted">
                        <CalendarClock size={11} aria-hidden /> 감염일 {h.dateCompromised}
                      </span>
                    )}
                    {h.firstSeenAt && (
                      <span className="inline-flex items-center gap-1 text-[11px] text-muted">
                        <CalendarClock size={11} aria-hidden /> 최초 탐지 {fmtDate(h.firstSeenAt)}
                      </span>
                    )}
                  </div>
                </div>
                <div className="mt-3 grid gap-2 text-[12px] sm:grid-cols-2 lg:grid-cols-4">
                  <div className="flex items-center gap-1.5"><Monitor size={13} className="shrink-0 text-slate-400" aria-hidden /><span className="text-muted">PC</span><span className="font-mono text-slate-700">{h.computerName ?? "—"}</span></div>
                  <div className="flex items-center gap-1.5"><Database size={13} className="shrink-0 text-slate-400" aria-hidden /><span className="text-muted">OS</span><span className="font-mono text-slate-700">{h.operatingSystem ?? "—"}</span></div>
                  <div className="flex items-center gap-1.5"><MapPin size={13} className="shrink-0 text-slate-400" aria-hidden /><span className="text-muted">IP</span><span className="font-mono text-slate-700">{h.ip ?? "—"}</span></div>
                  <div className="flex items-center gap-1.5"><ShieldAlert size={13} className="shrink-0 text-rose-400" aria-hidden /><span className="text-muted">탈취</span><span className="text-slate-700">사내 <strong className="text-rose-700">{h.totalCorporateServices}</strong> · 개인 {h.totalUserServices}</span></div>
                </div>
                {h.malwarePath && (
                  <div className="mt-2 flex items-start gap-1.5 text-[11px] text-slate-600">
                    <FileWarning size={12} className="mt-0.5 shrink-0 text-amber-500" aria-hidden /><span className="text-muted">악성코드 경로</span><span className="break-all font-mono">{h.malwarePath}</span>
                  </div>
                )}
                {h.antiviruses.length > 0 && (
                  <div className="mt-1 flex items-center gap-1.5 text-[11px] text-slate-600">
                    <ShieldCheck size={12} className="shrink-0 text-teal-500" aria-hidden /><span className="text-muted">감염 당시 백신</span><span>{h.antiviruses.join(", ")}</span>
                  </div>
                )}
                {(h.topLogins.length > 0 || h.topPasswords.length > 0) && (
                  <div className="mt-2 border-t border-slate-200 pt-2">
                    <span className="inline-flex items-center gap-1 text-[11px] font-semibold text-rose-700"><KeyRound size={11} aria-hidden /> 부분 마스킹 샘플</span>
                    {h.topLogins.length > 0 && (
                      <div className="mt-1 text-[11px] text-slate-600"><span className="text-muted">로그인</span> <span className="break-all font-mono">{h.topLogins.join(", ")}</span></div>
                    )}
                    {h.topPasswords.length > 0 && (
                      <div className="mt-0.5 text-[11px] text-slate-600"><span className="text-muted">비밀번호</span> <span className="break-all font-mono">{h.topPasswords.join(", ")}</span></div>
                    )}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </Panel>

      <Panel title="대응 가이드" subtitle="인포스틸러 감염 유형별 권고 조치 — 발견 시 이렇게 대응합니다">
        <div className="space-y-3">
          <div className="rounded-xl border border-rose-200 bg-rose-50/50 p-4">
            <div className="flex flex-wrap items-center gap-2 text-sm font-bold text-rose-800">
              <Monitor size={15} aria-hidden /> 임직원 단말 감염 (사내 침해)
              {infoEmp > 0
                ? <span className="rounded-full bg-rose-600 px-2 py-0.5 text-[10px] font-bold text-white">현재 {infoEmp}건</span>
                : <span className="rounded-full bg-teal-100 px-2 py-0.5 text-[10px] font-bold text-teal-700">현재 0건</span>}
            </div>
            <ol className="mt-2 list-decimal space-y-1 pl-5 text-[13px] leading-6 text-slate-700">
              <li>해당 단말 <strong>즉시 네트워크 격리</strong> + 보안팀 포렌식 (감염 시점·탈취 범위 확인)</li>
              <li>그 직원의 <strong>전 계정 비밀번호 재설정 + MFA 재등록</strong> (사내 SSO·메일·VPN·업무시스템)</li>
              <li><strong>활성 세션·토큰 전면 무효화</strong> (쿠키 탈취 시 비번 변경만으론 재로그인 차단 안 됨)</li>
              <li>단말 <strong>포맷/재설치</strong> 후 복귀, 동일 비번 재사용 계정 점검</li>
              <li>탈취 자격증명으로의 횡적 이동·이상 접근 로그 조사</li>
            </ol>
          </div>
          <div className="rounded-xl border border-amber-200 bg-amber-50/50 p-4">
            <div className="flex flex-wrap items-center gap-2 text-sm font-bold text-amber-800">
              <ShieldAlert size={15} aria-hidden /> 고객/사용자 단말 감염 (자격증명 탈취)
              {infoUsr > 0 && <span className="rounded-full bg-amber-600 px-2 py-0.5 text-[10px] font-bold text-white">현재 {infoUsr.toLocaleString()}건</span>}
            </div>
            <p className="mt-1 text-[12px] text-slate-600">고객 PC가 감염돼 우리 서비스 로그인 정보가 탈취된 경우(직접 침해는 아니나 계정 도용·이상거래 위험).</p>
            <ol className="mt-2 list-decimal space-y-1 pl-5 text-[13px] leading-6 text-slate-700">
              <li>위 「탈취된 로그인 페이지」 대상으로 <strong>이상거래탐지(FDS) 룰 강화</strong> + 의심 세션·IP 차단</li>
              <li>영향 가능 계정 <strong>비밀번호 강제 재설정·재로그인 유도</strong>, 해당 로그인에 <strong>step-up 인증</strong>(추가 OTP·기기인증) 적용</li>
              <li>고객 <strong>보안 통지</strong>: 개인 PC 백신 정밀검사·비번 변경·동일 비번 타 서비스 점검 안내</li>
              <li>탈취 URL 집중 모니터링(자동입력·비정상 로그인 패턴 탐지)</li>
            </ol>
          </div>
          <div className="rounded-xl border border-slate-200 bg-slate-50 p-4">
            <div className="flex flex-wrap items-center gap-2 text-sm font-bold text-slate-700">
              <Globe size={15} aria-hidden /> 서드파티 단말 감염
              {info3p > 0 && <span className="rounded-full bg-slate-500 px-2 py-0.5 text-[10px] font-bold text-white">현재 {info3p}건</span>}
            </div>
            <ol className="mt-2 list-decimal space-y-1 pl-5 text-[13px] leading-6 text-slate-700">
              <li>협력사·외주 단말로 추정 → 해당 업체 보안 점검 요청, 우리 시스템 접근 권한·세션 재검토</li>
              <li>외부 접근 경로(파트너 포털·API) 모니터링 강화</li>
            </ol>
          </div>
          <p className="flex gap-2 rounded-lg bg-slate-100 px-3 py-2 text-[12px] leading-5 text-slate-600"><Info size={14} className="mt-0.5 shrink-0 text-sky-600" aria-hidden /><span><strong>비번 변경만으론 부족한 이유</strong> — 인포스틸러는 <strong>세션 쿠키·토큰</strong>까지 탈취하므로 공격자는 비번 없이 기존 세션으로 로그인할 수 있습니다. 반드시 <strong>세션 무효화 + MFA</strong>를 병행하세요.</span></p>
        </div>
      </Panel>

      {sources.length > 0 && (
        <Panel title="수집 출처" subtitle="어떤 인텔리전스 소스에서 언제 수집했는지 기록">
          <div className="hidden overflow-x-auto sm:block">
            <table className="w-full min-w-[560px] text-sm">
              <thead>
                <tr className="border-b border-slate-200 text-left text-xs font-semibold uppercase tracking-wide text-muted">
                  <th className="px-3 py-2">소스</th><th className="px-3 py-2">종류</th><th className="px-3 py-2">엔드포인트</th><th className="px-3 py-2">수집</th><th className="px-3 py-2">시각</th>
                </tr>
              </thead>
              <tbody>
                {sources.map((s) => (
                  <tr key={s.name} className="border-b border-slate-100 last:border-0">
                    <td className="px-3 py-2 font-semibold text-ink"><Database size={13} className="mr-1 inline text-slate-400" aria-hidden />{s.name}</td>
                    <td className="px-3 py-2"><span className={`rounded-full border px-2 py-0.5 text-[11px] font-semibold ${s.kind === "infostealer" ? "border-rose-300 bg-rose-100 text-rose-700" : "border-sky-300 bg-sky-100 text-sky-700"}`}>{s.kind === "infostealer" ? "인포스틸러" : "데이터 유출"}</span></td>
                    <td className="px-3 py-2 font-mono text-[11px] text-muted">{s.endpoint}</td>
                    <td className="px-3 py-2 text-slate-700">{s.count.toLocaleString()}</td>
                    <td className="px-3 py-2 font-mono text-[11px] text-muted">{fmtDate(s.scannedAt)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {/* 모바일: 카드 */}
          <div className="space-y-2 sm:hidden">
            {sources.map((s) => (
              <div key={s.name} className="rounded-lg border border-slate-100 bg-slate-50 p-3">
                <div className="flex items-start justify-between gap-2">
                  <span className="inline-flex items-center gap-1.5 text-sm font-semibold text-ink"><Database size={13} className="shrink-0 text-slate-400" aria-hidden />{s.name}</span>
                  <span className={`shrink-0 rounded-full border px-2 py-0.5 text-[11px] font-semibold ${s.kind === "infostealer" ? "border-rose-300 bg-rose-100 text-rose-700" : "border-sky-300 bg-sky-100 text-sky-700"}`}>{s.kind === "infostealer" ? "인포스틸러" : "데이터 유출"}</span>
                </div>
                <div className="mt-1 break-all font-mono text-[11px] text-muted">{s.endpoint}</div>
                <div className="mt-1 text-[11px] text-muted">수집 {s.count.toLocaleString()}건 · {fmtDate(s.scannedAt)}</div>
              </div>
            ))}
          </div>
        </Panel>
      )}

      <Panel title="스캔 이력" subtitle="최근 스캔별 노출 건수 추이">
        {historyRecent.length ? (
          <ul className="grid gap-2 sm:grid-cols-2">
            {historyRecent.map((h) => (
              <li key={h.scannedAt} className="flex items-center justify-between rounded-lg border border-slate-100 bg-slate-50 px-3 py-2 text-sm">
                <span className="font-mono text-xs text-muted">{fmtDate(h.scannedAt)}</span>
                <span className="text-slate-700">총 <strong className="text-ink">{h.total}</strong>건
                  {h.newCount > 0 && <span className="ml-2 rounded-full bg-amber-100 px-1.5 py-0.5 text-[11px] font-bold text-amber-700">신규 {h.newCount}</span>}
                </span>
              </li>
            ))}
          </ul>
        ) : <p className="py-6 text-center text-sm text-muted">이력 없음.</p>}
      </Panel>

      <p className="flex flex-wrap items-center justify-center gap-x-2 gap-y-1 px-4 text-center text-[11px] leading-5 text-muted">
        <span className="inline-flex items-center gap-1"><ShieldCheck size={12} className="text-teal-600" aria-hidden /> 합법 인텔리전스 API(XposedOrNot·Hudson Rock·IntelX·LeakCheck) — 다크웹 직접 크롤링 없음</span>
        <span aria-hidden>·</span>
        <span>매일 자정(KST) Supabase 자동 배치</span>
        <span aria-hidden>·</span>
        <span>관리자 인증(RLS) 전용 · 외부 공유 금지</span>
      </p>
    </div>
  );
}

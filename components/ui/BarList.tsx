// 수평 바 리스트 — 분포/랭킹을 서버 렌더로 표현(라벨 + 값 + 비례 막대).
export type BarItem = {
  label: string;
  value: number;
  display?: string;
  color?: string;
  sublabel?: string;
};

const PALETTE = ["#0f766e", "#3157a4", "#b45309", "#be123c", "#0891b2", "#7c3aed", "#64748b", "#9333ea"];

export function BarList({
  items,
  unit = ""
}: {
  items: BarItem[];
  unit?: string;
}) {
  const max = items.reduce((m, it) => Math.max(m, it.value), 1);
  return (
    <div className="space-y-3">
      {items.map((it, i) => {
        const color = it.color ?? PALETTE[i % PALETTE.length];
        const pct = Math.max(2, Math.round((it.value / max) * 100));
        return (
          <div key={it.label}>
            <div className="mb-1 flex items-center justify-between gap-2 text-xs">
              <span className="truncate font-semibold text-ink">{it.label}</span>
              <span className="shrink-0 font-mono text-muted">
                {it.display ?? it.value.toLocaleString()}
                {unit}
                {it.sublabel ? <span className="ml-2 font-sans font-bold" style={{ color }}>{it.sublabel}</span> : null}
              </span>
            </div>
            <div className="barlist-track">
              <div className="barlist-fill" style={{ width: `${pct}%`, background: color }} />
            </div>
          </div>
        );
      })}
    </div>
  );
}

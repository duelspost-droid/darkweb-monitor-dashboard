import type { CSSProperties, ReactNode } from "react";

type Trend = { label: string; dir?: "up" | "down" | "neutral" };

// KPI 타일 — 좌측 액센트 레일 + 큰 숫자 + 아이콘 칩 + 추세 칩.
export function StatTile({
  label,
  value,
  unit,
  icon,
  accent = "#2dd4bf",
  trend,
  sub
}: {
  label: string;
  value: string | number;
  unit?: string;
  icon?: ReactNode;
  accent?: string;
  trend?: Trend;
  sub?: string;
}) {
  const chipClass =
    trend?.dir === "up" ? "chip chip-up" : trend?.dir === "down" ? "chip chip-down" : "chip chip-neutral";

  return (
    <div className="stat-tile" style={{ "--accent": accent } as CSSProperties}>
      <div className="flex items-start justify-between gap-2">
        <span className="text-sm font-medium text-muted">{label}</span>
        {icon ? (
          <span
            className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg"
            style={{
              // 틴티드 글래스 아이콘 칩 — 단색 원색 블록 대신 액센트 12~16% 틴트 + 헤어라인
              background: `color-mix(in srgb, ${accent} 16%, transparent)`,
              color: accent,
              boxShadow: `inset 0 0 0 1px color-mix(in srgb, ${accent} 35%, transparent)`
            }}
          >
            {icon}
          </span>
        ) : null}
      </div>
      <div className="flex items-end gap-1.5">
        <span className="stat-value">{value}</span>
        {unit ? <span className="mb-0.5 text-sm text-muted">{unit}</span> : null}
      </div>
      <div className="flex items-center justify-between gap-2">
        {trend ? <span className={chipClass}>{trend.label}</span> : <span />}
        {sub ? <span className="text-[11px] text-muted">{sub}</span> : null}
      </div>
    </div>
  );
}

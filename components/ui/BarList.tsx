import type { CSSProperties } from "react";

// 수평 바 리스트 — 분포/랭킹을 서버 렌더로 표현(라벨 + 값 + 비례 막대).
export type BarItem = {
  label: string;
  value: number;
  display?: string;
  color?: string;
  sublabel?: string;
};

// 다크 배경 위에서 선명한 밝은 톤(시맨틱: teal=정상, cobalt=정보, amber=경고, rose=위험)
const PALETTE = ["#2dd4bf", "#60a5fa", "#fbbf24", "#fb7185", "#22d3ee", "#a78bfa", "#94a3b8", "#c084fc"];

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
              {/* 색은 --bar-color 변수로 전달 — 그라디언트/하이라이트는 CSS(.barlist-fill)가 제어 */}
              <div className="barlist-fill" style={{ width: `${pct}%`, "--bar-color": color } as CSSProperties} />
            </div>
          </div>
        );
      })}
    </div>
  );
}

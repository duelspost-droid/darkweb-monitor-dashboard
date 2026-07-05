"use client";

import { useState, type ReactNode } from "react";
import { ChevronDown } from "lucide-react";

// 프리미엄 카드 컨테이너. 제목/부제 헤더 + 우측 슬롯 + 본문.
// collapsible=true 면 헤더(제목/쉐브론)를 눌러 본문을 접기/펼치기 한다.
// defaultCollapsed=true 면 처음에 접힌 상태로 렌더(참고용 패널을 기본 접힘으로 둘 때).
export function Panel({
  title,
  subtitle,
  right,
  children,
  bodyClassName = "p-5 pt-3",
  collapsible = false,
  defaultCollapsed = false,
}: {
  title?: string;
  subtitle?: string;
  right?: ReactNode;
  children: ReactNode;
  bodyClassName?: string;
  collapsible?: boolean;
  defaultCollapsed?: boolean;
}) {
  const [collapsed, setCollapsed] = useState(defaultCollapsed);
  const canCollapse = collapsible && !!title;
  const open = !canCollapse || !collapsed;
  return (
    <section className="surface surface-hover">
      {title ? (
        <div className={`flex flex-col gap-3 px-5 pt-5 sm:flex-row sm:items-start sm:justify-between ${open ? "" : "pb-5"}`}>
          <div className="flex min-w-0 items-start gap-2">
            {canCollapse ? (
              <button
                type="button"
                onClick={() => setCollapsed((c) => !c)}
                aria-expanded={open}
                aria-label={open ? "접기" : "펼치기"}
                className="mt-0.5 shrink-0 rounded-md p-0.5 text-muted transition hover:bg-slate-100 hover:text-ink"
              >
                <ChevronDown size={18} className={`transition-transform ${open ? "" : "-rotate-90"}`} aria-hidden />
              </button>
            ) : null}
            <div className="min-w-0">
              <h3
                className={`text-base font-bold text-ink ${canCollapse ? "cursor-pointer select-none" : ""}`}
                onClick={canCollapse ? () => setCollapsed((c) => !c) : undefined}
              >
                {title}
              </h3>
              {subtitle ? <p className="mt-1 text-sm text-muted">{subtitle}</p> : null}
            </div>
          </div>
          {right ? <div className="shrink-0 max-sm:w-full">{right}</div> : null}
        </div>
      ) : null}
      {open ? <div className={bodyClassName}>{children}</div> : null}
    </section>
  );
}

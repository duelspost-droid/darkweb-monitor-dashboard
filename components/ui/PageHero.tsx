import type { ReactNode } from "react";

// 페이지 상단의 프리미엄 그라디언트 히어로 헤더.
export function PageHero({
  kicker,
  title,
  description,
  right
}: {
  kicker: string;
  title: string;
  description?: string;
  right?: ReactNode;
}) {
  return (
    <section className="hero">
      <div className="relative z-10 flex flex-col gap-4 md:flex-row md:items-end md:justify-between">
        <div className="min-w-0">
          <span className="hero-kicker">{kicker}</span>
          <h2 className="hero-title">{title}</h2>
          {description ? <p className="hero-desc">{description}</p> : null}
        </div>
        {right ? <div className="shrink-0">{right}</div> : null}
      </div>
    </section>
  );
}

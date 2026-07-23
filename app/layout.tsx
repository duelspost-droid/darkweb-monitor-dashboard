import type { Metadata } from "next";
import { ShieldAlert } from "lucide-react";
import "./globals.css";

export const metadata: Metadata = {
  title: "다크웹 유출 모니터링",
  description: "회사 도메인 계정의 다크웹·유출 노출을 매일 자동 추적하는 대시보드"
};

export default function RootLayout({
  children
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="ko">
      {/* 웹폰트 — Pretendard Variable(본문·제목, dynamic subset) + JetBrains Mono(수치·모노).
          CDN 차단 시(사내망 등) 시스템 폰트로 조용히 폴백. */}
      <head>
        <link rel="preconnect" href="https://cdn.jsdelivr.net" crossOrigin="anonymous" />
        <link
          rel="stylesheet"
          href="https://cdn.jsdelivr.net/gh/orioncactus/pretendard@v1.3.9/dist/web/variable/pretendardvariable-dynamic-subset.min.css"
          crossOrigin="anonymous"
        />
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600&display=swap"
          rel="stylesheet"
        />
      </head>
      <body>
        <header className="topbar">
          <div className="topbar-inner">
            <span className="brand">
              <span className="brand-mark" aria-hidden>
                <ShieldAlert size={18} />
              </span>
              <span className="brand-text">
                다크웹 유출 모니터링
                <small>Credential Leak Monitor</small>
              </span>
            </span>
          </div>
        </header>
        <div className="content-shell">{children}</div>
      </body>
    </html>
  );
}

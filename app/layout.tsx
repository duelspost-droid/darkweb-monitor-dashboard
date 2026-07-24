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
      {/* 웹폰트 — 앱과 같은 출처(GitHub Pages)에서 셀프호스팅(@font-face in globals.css).
          사내망 CDN 차단과 무관하게 항상 로드됨. 미로드 시 시스템 폰트로 조용히 폴백.
          preload 로 초기 렌더 폰트만 우선 로드(FOUT 축소). */}
      <head>
        <link rel="preload" href="/fonts/PretendardVariable.woff2" as="font" type="font/woff2" crossOrigin="anonymous" />
        <link rel="preload" href="/fonts/JetBrainsMono-Regular.woff2" as="font" type="font/woff2" crossOrigin="anonymous" />
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

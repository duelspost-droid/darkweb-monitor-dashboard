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

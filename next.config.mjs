import { existsSync } from "node:fs";

// public/CNAME(커스텀 도메인) 가 있으면 루트(/) 배포 → basePath 없음.
// 없으면 GitHub Pages 프로젝트 사이트(/<repo>)로 PAGES_BASE_PATH 사용.
const hasCustomDomain = existsSync("public/CNAME");
const base = hasCustomDomain ? "" : (process.env.PAGES_BASE_PATH || "");

/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  ...(process.env.NEXT_OUTPUT === "export"
    ? {
        output: "export",
        basePath: base,
        assetPrefix: base,
        images: {
          unoptimized: true
        }
      }
    : {})
};

export default nextConfig;

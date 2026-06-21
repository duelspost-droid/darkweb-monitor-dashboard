/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  ...(process.env.NEXT_OUTPUT === "export"
    ? {
        output: "export",
        // GitHub Pages 프로젝트 사이트(/<repo>) 배포 시 PAGES_BASE_PATH 로 basePath 지정.
        basePath: process.env.PAGES_BASE_PATH || "",
        assetPrefix: process.env.PAGES_BASE_PATH || "",
        images: {
          unoptimized: true
        }
      }
    : {})
};

export default nextConfig;

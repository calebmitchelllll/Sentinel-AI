/** @type {import('next').NextConfig} */
const nextConfig = {
  reactStrictMode: true,
  experimental: { serverActions: { allowedOrigins: ["localhost:3000"] } },
  async rewrites() {
    return [
      {
        source: "/agents-stream/:path*",
        destination: `${process.env.NEMOCLAW_SERVICE_URL || "http://localhost:8000"}/:path*`,
      },
    ];
  },
};

module.exports = nextConfig;

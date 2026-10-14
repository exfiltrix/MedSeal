import os from "node:os";
import type { NextConfig } from "next";

// Opening the dev server from another device (http://<LAN IP>:3000) needs that host allowed.
// Every IPv4 address of this machine at startup is allowed; restart `npm run dev` after changing Wi-Fi.
const lanHosts = Object.values(os.networkInterfaces())
  .flat()
  .filter((a) => a && a.family === "IPv4" && !a.internal)
  .map((a) => a!.address);

// Security headers on every page and route (review round 1): the gateway/inbox pages hold staff
// sessions, so no other site may frame them (clickjacking), sniff types or read the referrer.
// A full script CSP is left out on purpose: the a11y init script is inline and the browser talks to
// a backend whose host is only known at runtime (src/lib/api.ts) — frame-ancestors is the part
// that matters here.
const securityHeaders = [
  { key: "X-Frame-Options", value: "DENY" },
  { key: "Content-Security-Policy", value: "frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'" },
  { key: "X-Content-Type-Options", value: "nosniff" },
  { key: "Referrer-Policy", value: "no-referrer" },
  { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
];

// Demo data must never ship: a production build with mocks on would show invented patients'
// results as real ones. MEDSEAL_DEMO_BUILD=1 is the explicit opt-in for a showcase build.
if (process.env.NODE_ENV === "production" && process.env.NEXT_PUBLIC_USE_MOCK === "1" && process.env.MEDSEAL_DEMO_BUILD !== "1") {
  throw new Error("NEXT_PUBLIC_USE_MOCK=1 in a production build: set MEDSEAL_DEMO_BUILD=1 if this is a demo build");
}

const nextConfig: NextConfig = {
  agentRules: false,
  output: "standalone", // self-contained server for the container image (Dockerfile)
  allowedDevOrigins: lanHosts,
  poweredByHeader: false,
  async headers() {
    return [{ source: "/:path*", headers: securityHeaders }];
  },
};

export default nextConfig;

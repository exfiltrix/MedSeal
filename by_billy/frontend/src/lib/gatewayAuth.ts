import { createHash, timingSafeEqual } from "crypto";

// Server-only (Node.js runtime — Next 16 Proxy defaults to it, so Node's `crypto` is available
// here and in route handlers alike). Never import this from a "use client" file.
//
// Every non-public page and API route sits behind HTTP Basic Auth (P1-01), checked twice: by
// src/proxy.ts (first line of defence) and again by each route handler (defence in depth).
//
// Review round 1:
// - One login per role. The Next.js server holds the backend's admin, doctor, device and client
//   tokens, so a single shared login made every staff member an admin. Each area now has its
//   own MEDSEAL_<AREA>_USER/PASSWORD; an area left unconfigured falls back to the shared
//   MEDSEAL_GATEWAY_USER/PASSWORD, so an existing .env.local keeps working until it is split.
// - CSRF. Browsers attach cached Basic credentials to cross-site requests too, so a page on
//   another site could make a logged-in browser seal, clear an inbox flag or start a crash test.
//   State-changing requests must come from this site (Sec-Fetch-Site / Origin).

export type StaffArea = "gateway" | "doctor" | "client" | "admin";

export type GatewayAuthResult =
  | { ok: true }
  | { ok: false; status: 401 | 403 | 503; message: string; area: StaffArea };

const AREA_ENV: Record<StaffArea, string> = {
  gateway: "GATEWAY",
  doctor: "DOCTOR",
  client: "CLIENT",
  admin: "ADMIN",
};

// Which login a protected path needs. Matches the matcher in src/proxy.ts.
export function areaForPath(pathname: string): StaffArea {
  if (/^\/(api\/)?inbox(\/|$)|^\/api\/automation(\/|$)/.test(pathname)) return "doctor";
  if (/^\/(api\/)?client(\/|$)/.test(pathname)) return "client";
  if (/^\/api\/(crash-test|passport)(\/|$)/.test(pathname)) return "admin";
  return "gateway";
}

function safeEqual(a: string, b: string): boolean {
  // Hash first so timingSafeEqual always receives equal-length buffers. This avoids
  // exposing the configured credential length through a fast-path length check.
  const digestA = createHash("sha256").update(a, "utf8").digest();
  const digestB = createHash("sha256").update(b, "utf8").digest();
  return timingSafeEqual(digestA, digestB);
}

function credentialsFor(area: StaffArea): { user?: string; pass?: string } {
  const key = AREA_ENV[area];
  const user = process.env[`MEDSEAL_${key}_USER`];
  const pass = process.env[`MEDSEAL_${key}_PASSWORD`];
  if (user && pass) return { user, pass };
  return { user: process.env.MEDSEAL_GATEWAY_USER, pass: process.env.MEDSEAL_GATEWAY_PASSWORD };
}

const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

// A state-changing request must come from this site. Browsers always send Sec-Fetch-Site and/or
// Origin on cross-site requests; a request with neither is not from a browser (curl, scripts/e2e),
// so it carries no ambient credentials to abuse and is left to the Basic Auth check.
export function isCrossSite(method: string, headers: Headers): boolean {
  if (SAFE_METHODS.has(method.toUpperCase())) return false;
  const site = headers.get("sec-fetch-site");
  if (site && site !== "same-origin" && site !== "none") return true;
  const origin = headers.get("origin");
  if (!origin) return false;
  const host = headers.get("x-forwarded-host") ?? headers.get("host");
  try {
    return new URL(origin).host !== host;
  } catch {
    return true; // "null" or garbage: an opaque origin is never this site
  }
}

export function checkStaffAuth(req: Request, area: StaffArea): GatewayAuthResult {
  if (isCrossSite(req.method, req.headers)) {
    return { ok: false, status: 403, message: "Cross-site request refused", area };
  }
  // Explicit opt-out for a trusted demo network only; any other value (or unset) keeps the gate.
  if (process.env.MEDSEAL_GATEWAY_AUTH === "off") return { ok: true };

  const { user, pass } = credentialsFor(area);
  if (!user || !pass) {
    // Fail closed, never open: an unconfigured gateway must not become an open gateway.
    return {
      ok: false,
      status: 503,
      message: `Credentials are not configured (MEDSEAL_${AREA_ENV[area]}_USER/PASSWORD or MEDSEAL_GATEWAY_USER/PASSWORD)`,
      area,
    };
  }

  const header = req.headers.get("authorization");
  if (header?.startsWith("Basic ")) {
    const decoded = Buffer.from(header.slice(6), "base64").toString("utf-8");
    const sep = decoded.indexOf(":");
    const u = sep === -1 ? decoded : decoded.slice(0, sep);
    const p = sep === -1 ? "" : decoded.slice(sep + 1);
    const userMatches = safeEqual(u, user);
    const passwordMatches = safeEqual(p, pass);
    if (userMatches && passwordMatches) return { ok: true };
  }

  return { ok: false, status: 401, message: "Authentication required", area };
}

export function unauthorizedResponse(result: Extract<GatewayAuthResult, { ok: false }>) {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  // A realm per area: the browser keeps separate saved logins for the doctor and the admin.
  if (result.status === 401) headers["WWW-Authenticate"] = `Basic realm="MedSeal ${result.area}"`;
  return new Response(JSON.stringify({ detail: result.message }), { status: result.status, headers });
}

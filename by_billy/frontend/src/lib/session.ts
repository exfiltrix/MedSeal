import { NextRequest, NextResponse } from "next/server";

// Server-only (route handlers and src/proxy.ts). Never import this from a "use client" file.
//
// Personal sign-in (production): the backend issues a session token at POST /auth/login; the
// browser only ever holds it in an httpOnly, SameSite=Strict cookie (JavaScript cannot read it,
// other sites cannot send it), and these route handlers forward it as the bearer token. Every role
// decision is the backend's: a doctor's token simply gets 403 from an admin endpoint.
//
// CSRF: SameSite=Strict already keeps the cookie off cross-site requests; state-changing requests
// must also come from this site (Sec-Fetch-Site / Origin) — two independent barriers.

export const SESSION_COOKIE = "medseal_session";
export const BACKEND_URL = (process.env.MEDSEAL_BACKEND_URL ?? process.env.NEXT_PUBLIC_API_URL ?? "").replace(/\/$/, "");
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

export function isCrossSite(method: string, headers: Headers): boolean {
  if (SAFE_METHODS.has(method.toUpperCase())) return false;
  const site = headers.get("sec-fetch-site");
  if (site && site !== "same-origin" && site !== "none") return true;
  const origin = headers.get("origin");
  if (!origin) return false; // not a browser: carries no ambient cookie to abuse
  const host = headers.get("x-forwarded-host") ?? headers.get("host");
  try {
    return new URL(origin).host !== host;
  } catch {
    return true; // "null" or garbage: an opaque origin is never this site
  }
}

export function cookieOptions(maxAgeSeconds: number) {
  return {
    httpOnly: true,
    sameSite: "strict" as const,
    // Secure everywhere but plain-http development; MEDSEAL_COOKIE_SECURE=0 only for a lab setup.
    secure: process.env.NODE_ENV === "production" && process.env.MEDSEAL_COOKIE_SECURE !== "0",
    path: "/",
    maxAge: maxAgeSeconds,
  };
}

const json = (detail: string, status: number) => NextResponse.json({ detail }, { status });

export type Gate = { ok: true; token: string } | { ok: false; response: NextResponse };

// The signed-in user's token for this request, or the response to send instead.
export function sessionGate(req: NextRequest): Gate {
  if (isCrossSite(req.method, req.headers)) return { ok: false, response: json("Cross-site request refused", 403) };
  if (!BACKEND_URL) return { ok: false, response: json("Not configured: set MEDSEAL_BACKEND_URL", 503) };
  const token = req.cookies.get(SESSION_COOKIE)?.value;
  if (!token) return { ok: false, response: json("Not signed in", 401) };
  return { ok: true, token };
}

export async function forward(path: string, token: string, init: RequestInit = {}): Promise<NextResponse> {
  const res = await fetch(`${BACKEND_URL}${path}`, {
    cache: "no-store",
    ...init,
    headers: { ...init.headers, Authorization: `Bearer ${token}` },
  });
  const contentType = res.headers.get("content-type") ?? "application/json";
  if (!contentType.includes("application/json")) {
    return new NextResponse(await res.arrayBuffer(), {
      status: res.status,
      headers: {
        "Content-Type": contentType,
        "Content-Disposition": res.headers.get("content-disposition") ?? "attachment",
      },
    });
  }
  return new NextResponse(await res.text(), { status: res.status, headers: { "Content-Type": contentType } });
}

// Gate + forward in one step: what nearly every protected route handler does.
export async function proxyAsUser(req: NextRequest, path: string, init: RequestInit = {}): Promise<NextResponse> {
  const gate = sessionGate(req);
  if (!gate.ok) return gate.response;
  return forward(path, gate.token, init);
}

export type Me = { id: number; username: string; full_name: string; role: string; hospital: string; must_change_password: boolean };

// For the few handlers that act with a machine credential (web sealing uses the gateway's device
// token): the user's role is checked against the backend first, so the device token only ever
// works for a signed-in operator or admin.
export async function requireRole(req: NextRequest, roles: string[]): Promise<{ ok: true; me: Me } | { ok: false; response: NextResponse }> {
  const gate = sessionGate(req);
  if (!gate.ok) return gate;
  const res = await fetch(`${BACKEND_URL}/auth/me`, { headers: { Authorization: `Bearer ${gate.token}` }, cache: "no-store" });
  if (!res.ok) return { ok: false, response: json("Not signed in", 401) };
  const me = (await res.json()) as Me;
  if (me.must_change_password) return { ok: false, response: json("Password change required", 403) };
  if (!roles.includes(me.role)) return { ok: false, response: json(`Role required: ${roles.join(" or ")}`, 403) };
  return { ok: true, me };
}

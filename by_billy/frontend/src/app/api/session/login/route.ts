import { NextRequest, NextResponse } from "next/server";
import { BACKEND_URL, SESSION_COOKIE, cookieOptions, isCrossSite } from "@/lib/session";

// Sign-in: the backend checks password (+ TOTP for admins) and returns a session token, which goes
// straight into an httpOnly cookie — the page's JavaScript never sees it.
export async function POST(req: NextRequest) {
  if (isCrossSite(req.method, req.headers)) return NextResponse.json({ detail: "Cross-site request refused" }, { status: 403 });
  if (!BACKEND_URL) return NextResponse.json({ detail: "Not configured: set MEDSEAL_BACKEND_URL" }, { status: 503 });
  const res = await fetch(`${BACKEND_URL}/auth/login`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      // the backend's per-IP limits and audit see the real client, not this server
      "X-Forwarded-For": req.headers.get("x-forwarded-for") ?? "",
    },
    body: await req.text(),
    cache: "no-store",
  });
  const body = await res.json().catch(() => ({ detail: "Sign-in failed" }));
  if (!res.ok) return NextResponse.json({ detail: body.detail ?? "Sign-in failed" }, { status: res.status });
  const expires = Date.parse(body.expires_at);
  const maxAge = Number.isNaN(expires) ? 12 * 3600 : Math.max(60, Math.floor((expires - Date.now()) / 1000));
  const out = NextResponse.json({ user: body.user });
  out.cookies.set(SESSION_COOKIE, body.token, cookieOptions(maxAge));
  return out;
}

import { NextRequest, NextResponse } from "next/server";
import { SESSION_COOKIE, cookieOptions, forward, sessionGate } from "@/lib/session";

// Revoke the session on the backend, then drop the cookie (even if the backend call fails).
export async function POST(req: NextRequest) {
  const gate = sessionGate(req);
  if (gate.ok) await forward("/auth/logout", gate.token, { method: "POST" }).catch(() => undefined);
  const out = NextResponse.json({ ok: true });
  out.cookies.set(SESSION_COOKIE, "", cookieOptions(0));
  return out;
}

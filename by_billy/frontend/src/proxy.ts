import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { SESSION_COOKIE, isCrossSite } from "@/lib/session";

// First barrier in front of everything that needs a signed-in person (personal accounts; the
// backend decides roles). Pages without a session cookie go to /login and come back afterwards;
// API routes answer 401. State-changing requests from another site are refused (CSRF), on top of
// the SameSite=Strict cookie. Each route handler re-checks independently (src/lib/session.ts).
const PAGES = ["/seal", "/inbox", "/client", "/account", "/admin"];

export function proxy(request: NextRequest) {
  const { pathname, search } = request.nextUrl;
  if (isCrossSite(request.method, request.headers)) {
    return NextResponse.json({ detail: "Cross-site request refused" }, { status: 403 });
  }
  if (pathname.startsWith("/api/session/login")) return NextResponse.next();
  if (request.cookies.get(SESSION_COOKIE)?.value) return NextResponse.next();
  if (pathname.startsWith("/api/")) return NextResponse.json({ detail: "Not signed in" }, { status: 401 });
  const login = new URL("/login", request.url);
  login.searchParams.set("next", PAGES.some((p) => pathname.startsWith(p)) ? pathname + search : "/");
  return NextResponse.redirect(login);
}

export const config = {
  matcher: [
    "/seal", "/inbox", "/client", "/account", "/admin/:path*",
    "/api/seal/:path*", "/api/seal", "/api/crash-test/:path*", "/api/crash-test", "/api/passport/:path*", "/api/passport",
    "/api/inbox/:path*", "/api/inbox", "/api/automation/:path*", "/api/automation", "/api/client/:path*",
    "/api/session/:path*", "/api/admin/:path*",
  ],
};

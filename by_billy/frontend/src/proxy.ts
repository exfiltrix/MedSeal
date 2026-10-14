import { NextResponse } from "next/server";
import type { NextRequest } from "next/server";
import { areaForPath, checkStaffAuth, unauthorizedResponse } from "@/lib/gatewayAuth";

// P1-01: the /seal page (gateway simulator), the doctor's /inbox, the client cabinet and every
// gateway/admin API route require HTTP Basic Auth — with a separate login per area (gateway,
// doctor, client, admin; see src/lib/gatewayAuth.ts) and a same-site check on state-changing
// requests (CSRF). This is the first line of defence; each route handler re-checks independently.
export function proxy(request: NextRequest) {
  const result = checkStaffAuth(request, areaForPath(request.nextUrl.pathname));
  if (result.ok) return NextResponse.next();
  return unauthorizedResponse(result);
}

export const config = {
  matcher: [
    "/seal",
    "/api/seal",
    "/api/seal/:path*",
    "/api/crash-test",
    "/api/crash-test/:path*",
    "/api/passport",
    "/api/passport/:path*",
    "/inbox",
    "/api/inbox",
    "/api/inbox/:path*",
    "/api/automation",
    "/api/automation/:path*",
    "/client",
    "/api/client",
    "/api/client/:path*",
  ],
};

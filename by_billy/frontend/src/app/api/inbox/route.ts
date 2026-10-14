import { NextRequest } from "next/server";
import { proxyAsUser } from "@/lib/session";

// The doctor's inbox, with the signed-in user's own session (src/lib/session.ts); the backend
// decides whether that user may see it (doctor or admin role).
export async function GET(req: NextRequest) {
  return proxyAsUser(req, `/inbox${req.nextUrl.search}`);
}

export async function POST(req: NextRequest) {
  return proxyAsUser(req, "/inbox", { method: "POST", body: await req.formData() });
}

import { NextRequest } from "next/server";
import { proxyAsUser } from "@/lib/session";

// Issuing a passport is an admin action: the backend checks the signed-in user's role.
export async function POST(req: NextRequest) {
  return proxyAsUser(req, "/passport", { method: "POST", headers: { "Content-Type": "application/json" }, body: await req.text() });
}

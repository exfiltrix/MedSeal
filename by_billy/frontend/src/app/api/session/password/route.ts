import { NextRequest } from "next/server";
import { proxyAsUser } from "@/lib/session";

export async function POST(req: NextRequest) {
  return proxyAsUser(req, "/auth/password", { method: "POST", headers: { "Content-Type": "application/json" }, body: await req.text() });
}

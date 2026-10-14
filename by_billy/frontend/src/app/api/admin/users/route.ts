import { NextRequest } from "next/server";
import { proxyAsUser } from "@/lib/session";

// User administration: the backend allows it to admins only.
export async function GET(req: NextRequest) {
  return proxyAsUser(req, "/users");
}

export async function POST(req: NextRequest) {
  return proxyAsUser(req, "/users", { method: "POST", headers: { "Content-Type": "application/json" }, body: await req.text() });
}

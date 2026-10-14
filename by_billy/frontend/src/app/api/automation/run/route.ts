import { NextRequest } from "next/server";
import { proxyAsUser } from "@/lib/session";

export async function POST(req: NextRequest) {
  return proxyAsUser(req, "/automation/run", { method: "POST" });
}

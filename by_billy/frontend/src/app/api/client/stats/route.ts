import { NextRequest } from "next/server";
import { proxyAsUser } from "@/lib/session";

export async function GET(req: NextRequest) {
  return proxyAsUser(req, "/client/stats");
}

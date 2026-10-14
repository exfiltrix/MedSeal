import { NextRequest } from "next/server";
import { proxyAsUser } from "@/lib/session";

// The client cabinet: the backend scopes every answer to the signed-in client's own hospital.
export async function GET(req: NextRequest) {
  return proxyAsUser(req, "/client/devices");
}

import { NextRequest } from "next/server";
import { checkStaffAuth, unauthorizedResponse } from "@/lib/gatewayAuth";
import { BACKEND_URL, forward, notConfigured } from "@/lib/serverProxy";

export async function GET(req: NextRequest) {
  const auth = checkStaffAuth(req, "client");
  if (!auth.ok) return unauthorizedResponse(auth);
  const token = process.env.MEDSEAL_CLIENT_TOKEN;
  if (!BACKEND_URL || !token) return notConfigured("MEDSEAL_CLIENT_TOKEN");
  return forward("/client/stats", token, { cache: "no-store" });
}

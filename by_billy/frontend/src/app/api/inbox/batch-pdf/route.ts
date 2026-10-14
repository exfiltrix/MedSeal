import { NextRequest } from "next/server";
import { checkStaffAuth, unauthorizedResponse } from "@/lib/gatewayAuth";
import { BACKEND_URL, forward, notConfigured } from "@/lib/serverProxy";

export async function POST(req: NextRequest) {
  const auth = checkStaffAuth(req, "doctor");
  if (!auth.ok) return unauthorizedResponse(auth);
  const token = process.env.MEDSEAL_DOCTOR_TOKEN;
  if (!BACKEND_URL || !token) return notConfigured("MEDSEAL_DOCTOR_TOKEN");
  const body = await req.text();
  return forward(`/inbox/batch-pdf${req.nextUrl.search}`, token, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body,
  });
}

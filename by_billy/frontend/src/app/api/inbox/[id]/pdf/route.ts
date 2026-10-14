import { NextRequest, NextResponse } from "next/server";
import { checkStaffAuth, unauthorizedResponse } from "@/lib/gatewayAuth";
import { BACKEND_URL, forward, notConfigured } from "@/lib/serverProxy";

export async function GET(req: NextRequest, context: { params: Promise<{ id: string }> }) {
  const auth = checkStaffAuth(req, "doctor");
  if (!auth.ok) return unauthorizedResponse(auth);
  const token = process.env.MEDSEAL_DOCTOR_TOKEN;
  if (!BACKEND_URL || !token) return notConfigured("MEDSEAL_DOCTOR_TOKEN");
  const { id } = await context.params;
  if (!/^\d+$/.test(id)) return NextResponse.json({ detail: "Invalid inbox id" }, { status: 400 });
  return forward(`/inbox/${id}/pdf${req.nextUrl.search}`, token, { cache: "no-store" });
}

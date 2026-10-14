import { NextRequest, NextResponse } from "next/server";
import { BACKEND_URL, requireRole } from "@/lib/session";

// The sealed original, downloaded with the gateway's device token for a signed-in operator/admin.
export async function GET(req: NextRequest, context: { params: Promise<{ id: string }> }) {
  const allowed = await requireRole(req, ["operator", "admin"]);
  if (!allowed.ok) return allowed.response;
  const token = process.env.MEDSEAL_DEVICE_TOKEN;
  if (!token) return NextResponse.json({ detail: "Gateway is not configured: set MEDSEAL_DEVICE_TOKEN" }, { status: 503 });
  const { id } = await context.params;
  if (!/^\d+$/.test(id)) return NextResponse.json({ detail: "Invalid seal id" }, { status: 400 });
  const res = await fetch(`${BACKEND_URL}/seal/${id}/file`, { headers: { Authorization: `Bearer ${token}` }, cache: "no-store" });
  if (!res.ok) return new NextResponse(await res.text(), { status: res.status });
  return new NextResponse(await res.arrayBuffer(), {
    status: res.status,
    headers: {
      "Content-Type": res.headers.get("content-type") ?? "application/octet-stream",
      "Content-Disposition": res.headers.get("content-disposition") ?? `attachment; filename="medseal-seal-${id}"`,
    },
  });
}

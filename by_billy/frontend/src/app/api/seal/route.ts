import { NextRequest, NextResponse } from "next/server";
import { BACKEND_URL, requireRole } from "@/lib/session";

// Web sealing acts as the hospital's gateway device: the device token (MEDSEAL_DEVICE_TOKEN) is a
// server-only machine credential, and it is used only for a signed-in operator or admin — the
// role is checked against the backend first (src/lib/session.ts: requireRole).
const MAX_UPLOAD_BYTES = 50 * 1024 * 1024;

export async function POST(req: NextRequest) {
  const allowed = await requireRole(req, ["operator", "admin"]);
  if (!allowed.ok) return allowed.response;
  const token = process.env.MEDSEAL_DEVICE_TOKEN;
  if (!token) return NextResponse.json({ detail: "Gateway is not configured: set MEDSEAL_DEVICE_TOKEN" }, { status: 503 });

  // Reject an oversize body before req.formData() buffers it into memory.
  const contentLength = Number(req.headers.get("content-length"));
  if (!contentLength || Number.isNaN(contentLength) || contentLength > MAX_UPLOAD_BYTES) {
    return NextResponse.json({ detail: "File is too large" }, { status: 413 });
  }
  const res = await fetch(`${BACKEND_URL}/seal`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}`, "X-MedSeal-Operator": allowed.me.username },
    body: await req.formData(),
  });
  return new NextResponse(await res.text(), { status: res.status, headers: { "Content-Type": "application/json" } });
}

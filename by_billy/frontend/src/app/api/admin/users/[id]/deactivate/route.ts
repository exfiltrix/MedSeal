import { NextRequest, NextResponse } from "next/server";
import { proxyAsUser } from "@/lib/session";

export async function POST(req: NextRequest, context: { params: Promise<{ id: string }> }) {
  const { id } = await context.params;
  if (!/^\d+$/.test(id)) return NextResponse.json({ detail: "Invalid id" }, { status: 400 });
  return proxyAsUser(req, `/users/${id}/deactivate`, { method: "POST" });
}

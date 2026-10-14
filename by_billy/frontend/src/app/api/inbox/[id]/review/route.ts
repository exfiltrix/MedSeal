import { NextRequest, NextResponse } from "next/server";
import { proxyAsUser } from "@/lib/session";

const isId = (id: string) => /^\d+$/.test(id);
const badId = () => NextResponse.json({ detail: "Invalid id" }, { status: 400 });
type Ctx = { params: Promise<{ id: string }> };

export async function POST(req: NextRequest, context: Ctx) {
  const { id } = await context.params;
  return isId(id) ? proxyAsUser(req, `/inbox/${id}/review`, { method: "POST" }) : badId();
}

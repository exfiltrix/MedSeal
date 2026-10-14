// Browser side of personal sign-in. The session token itself is an httpOnly cookie the page can
// never read; these calls go to same-origin route handlers (src/app/api/session/**, /api/admin/**).
import { ApiError } from "./api";

export type Role = "admin" | "doctor" | "operator" | "auditor" | "client";
export type Me = {
  id: number;
  username: string;
  full_name: string;
  role: Role;
  hospital: string;
  active: boolean;
  mfa: boolean;
  must_change_password: boolean;
};
export type CreatedUser = Me & { mfa_provisioning_uri?: string };

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(path, {
    ...init,
    headers: init?.body ? { "Content-Type": "application/json", ...init?.headers } : init?.headers,
  });
  const text = await res.text();
  let detail = text;
  try {
    detail = JSON.parse(text).detail ?? text;
  } catch {
    // not JSON
  }
  if (!res.ok) throw new ApiError(res.status, typeof detail === "string" ? detail : res.statusText);
  return (text ? JSON.parse(text) : undefined) as T;
}

const post = <T,>(path: string, body?: unknown) =>
  call<T>(path, { method: "POST", body: body === undefined ? undefined : JSON.stringify(body) });

export const sessionApi = {
  login: (username: string, password: string, totp?: string) =>
    post<{ user: Me }>("/api/session/login", { username, password, totp: totp || null }),
  logout: () => post<{ ok: true }>("/api/session/logout"),
  me: () => call<Me>("/api/session/me"),
  changePassword: (current: string, next: string) => post<Me>("/api/session/password", { current, new: next }),
  users: () => call<Me[]>("/api/admin/users"),
  createUser: (body: { username: string; role: Role; password: string; full_name?: string; hospital?: string }) =>
    post<CreatedUser>("/api/admin/users", body),
  deactivate: (id: number) => post<Me>(`/api/admin/users/${id}/deactivate`),
  reset: (id: number, password: string, resetMfa: boolean) =>
    post<CreatedUser>(`/api/admin/users/${id}/reset`, { password, reset_mfa: resetMfa }),
};

export { redirectForAuth } from "./api";

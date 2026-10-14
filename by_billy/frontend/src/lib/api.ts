import type {
  AiModel,
  AutomationStatus,
  CheckFileResult,
  CheckInfo,
  ClientAlert,
  ClientDevice,
  ClientStats,
  CrashTestJob,
  InboxItem,
  InboxListing,
  InboxQuery,
  CrashTestRequest,
  Passport,
  PassportSummary,
  SealResponse,
  Stats,
  VerifyResponse,
} from "./types";
import { mockApi } from "./mock";

// Mock data is opt-in. A missing backend URL is a configuration error, never a silent fake.
const RAW_BASE = process.env.NEXT_PUBLIC_API_URL?.replace(/\/$/, "");
export const USE_MOCK = process.env.NEXT_PUBLIC_USE_MOCK === "1";

// With NEXT_PUBLIC_API_URL=http://localhost:8000/api the site also works when opened from another
// device (http://<laptop IP>:3000): the browser then talks to the backend on that same host.
function resolveBase(raw: string | undefined): string {
  if (!raw || typeof window === "undefined") return raw ?? "";
  const url = new URL(raw);
  if (["localhost", "127.0.0.1"].includes(url.hostname)) url.hostname = window.location.hostname;
  return url.toString().replace(/\/$/, "");
}

export const API_BASE_URL = resolveBase(RAW_BASE);

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
  }
}

function ensureBackendConfigured(): void {
  if (!API_BASE_URL) {
    throw new ApiError(503, "Backend is not configured: set NEXT_PUBLIC_API_URL or explicitly enable NEXT_PUBLIC_USE_MOCK=1");
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  ensureBackendConfigured();
  const isForm = init?.body instanceof FormData;
  const res = await fetch(`${API_BASE_URL}${path}`, {
    ...init,
    headers: isForm ? init?.headers : { "Content-Type": "application/json", ...init?.headers },
  });
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new ApiError(res.status, detailOf(text) || res.statusText);
  }
  return res.json() as Promise<T>;
}

// FastAPI errors are {"detail": "message"} or, for validation, {"detail": [{"msg": ...}, ...]}.
function detailOf(text: string): string {
  try {
    const { detail } = JSON.parse(text);
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail)) return detail.map((x) => x?.msg ?? String(x)).join("; ");
  } catch {
    // not JSON: show as is
  }
  return text;
}

const post = <T>(path: string, body: unknown) =>
  request<T>(path, {
    method: "POST",
    body: body instanceof FormData ? body : JSON.stringify(body),
  });

// A protected call answered "not signed in" or "change your password first": take the person
// there and back (src/proxy.ts and the backend decide; this only follows). -> true if navigating.
export function redirectForAuth(e: unknown): boolean {
  if (!(e instanceof ApiError) || typeof window === "undefined") return false;
  const here = window.location.pathname + window.location.search;
  if (e.status === 401) {
    // eslint-disable-next-line @next/next/no-location-assign-relative-destination -- full reload on purpose: no data of the previous session may stay in memory
    window.location.assign(`/login?next=${encodeURIComponent(here)}`);
    return true;
  }
  if (e.status === 403 && /password change required/i.test(e.message)) {
    // eslint-disable-next-line @next/next/no-location-assign-relative-destination -- full reload on purpose: no data of the previous session may stay in memory
    window.location.assign(`/account?next=${encodeURIComponent(here)}`);
    return true;
  }
  return false;
}

async function throwIfNotOk(res: Response): Promise<string> {
  const text = await res.text();
  if (!res.ok) {
    const error = new ApiError(res.status, detailOf(text) || res.statusText);
    redirectForAuth(error);
    throw error;
  }
  return text;
}

// Same-origin Next.js route handler (src/app/api/**), not the backend directly: it forwards the
// signed-in user's session (an httpOnly cookie the page cannot read) as the bearer token.
async function viaProxy<T>(path: string, init?: RequestInit): Promise<T> {
  ensureBackendConfigured();
  const text = await throwIfNotOk(await fetch(path, init));
  return (text ? JSON.parse(text) : undefined) as T;
}

function queryString(params: Record<string, string | number | boolean | undefined>): string {
  const q = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) if (v !== undefined && v !== "") q.set(k, String(v));
  const s = q.toString();
  return s ? `?${s}` : "";
}

// download_url from the backend is absolute-path ("/api/seal/12/file").
export function backendUrl(path: string): string {
  if (USE_MOCK || /^https?:|^data:/.test(path)) return path;
  if (!API_BASE_URL) return path;
  if (path.startsWith("/api/seal/") && path.endsWith("/file")) return path;
  return new URL(path, `${API_BASE_URL}/`).toString();
}

export function pngSrc(b64OrUrl: string): string {
  if (!b64OrUrl) return "";
  if (/^(data:|https?:|\/)/.test(b64OrUrl)) return b64OrUrl;
  return `data:image/png;base64,${b64OrUrl}`;
}

const realApi = {
  // Goes through the Next.js route handler (src/app/api/seal/route.ts): the device token that
  // authorizes sealing is a server-only secret, used only for a signed-in operator or admin.
  seal: (file: File) => {
    ensureBackendConfigured();
    const form = new FormData();
    form.append("file", file);
    return viaProxy<SealResponse>("/api/seal", { method: "POST", body: form });
  },

  verify: (file: File) => {
    const form = new FormData();
    form.append("file", file);
    return post<VerifyResponse>("/verify", form);
  },

  // Doctor's inbox: images are verified automatically, most urgent first. Goes through the
  // Next.js route handlers (src/app/api/inbox/**) with the signed-in doctor's own session.
  uploadToInbox: (files: File[]) => {
    ensureBackendConfigured();
    const form = new FormData();
    files.forEach((f) => form.append("files", f));
    return viaProxy<InboxItem[]>("/api/inbox", { method: "POST", body: form });
  },
  getInbox: (query: InboxQuery = {}) => viaProxy<InboxListing>(`/api/inbox${queryString(query)}`),
  getInboxItem: (id: number) =>
    viaProxy<InboxItem & { result: VerifyResponse | { error: string } }>(`/api/inbox/${id}`),
  reviewInboxItem: (id: number) => viaProxy<InboxItem>(`/api/inbox/${id}/review`, { method: "POST" }),
  getAutomation: () => viaProxy<AutomationStatus>("/api/automation"),
  runAutomation: () => viaProxy<{ sealed: number; verified: number }>("/api/automation/run", { method: "POST" }),
  inboxItemPdfUrl: (id: number, lang: "uz" | "ru" | "en") => `/api/inbox/${id}/pdf?lang=${lang}`,
  // Batch PDF is POST-only on the backend; fetch it here and hand back an object URL an <a> can
  // point at, since the browser needs a GET-able link to open/download a file.
  batchPdfUrl: async (ids: number[], lang: "uz" | "ru" | "en") => {
    ensureBackendConfigured();
    const res = await fetch(`/api/inbox/batch-pdf?lang=${lang}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ids }),
    });
    if (!res.ok) await throwIfNotOk(res);
    return URL.createObjectURL(await res.blob());
  },

  // Client (hospital/clinic) cabinet: the backend scopes it to the signed-in client's hospital.
  getClientDevices: () => viaProxy<ClientDevice[]>("/api/client/devices"),
  getClientStats: () => viaProxy<ClientStats>("/api/client/stats"),
  getClientAlerts: (limit = 50) => viaProxy<ClientAlert[]>(`/api/client/alerts?limit=${limit}`),
  getClientPassports: () => viaProxy<PassportSummary[]>("/api/client/passports"),

  // Public QR check (no login): the page lives at /check/{token} on this site.
  getCheck: (token: string) => request<CheckInfo>(`/check/${encodeURIComponent(token)}`),
  checkFile: (token: string, file: File) => {
    const form = new FormData();
    form.append("file", file);
    return post<CheckFileResult>(`/check/${encodeURIComponent(token)}`, form);
  },
  checkQrUrl: (token: string, pageUrl: string) =>
    `${API_BASE_URL}/check/${encodeURIComponent(token)}/qr.png?url=${encodeURIComponent(pageUrl)}`,

  getModels: () => request<AiModel[]>("/models"),
  // Admin actions (P1-04) go through Next.js route handlers with the signed-in admin's session;
  // the backend refuses anyone else.
  startCrashTest: (body: CrashTestRequest) => {
    ensureBackendConfigured();
    return viaProxy<{ job_id: number }>("/api/crash-test", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  },

  getCrashTest: (jobId: number) => request<CrashTestJob>(`/crash-test/${jobId}`),

  createPassport: (modelId: number, crashTestId: number) => {
    ensureBackendConfigured();
    return viaProxy<Passport>("/api/passport", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ model_id: modelId, crash_test_id: crashTestId }),
    });
  },
  getPassport: (id: number) => request<Passport>(`/passport/${id}`),
  passportPdfUrl: (id: number, lang: "uz" | "ru" | "en") =>
    backendUrl(`${API_BASE_URL}/passport/${id}/pdf?lang=${lang}`),

  getStats: () => request<Stats>("/stats"),
};

export type Api = typeof realApi;

export const api: Api = USE_MOCK ? mockApi : realApi;

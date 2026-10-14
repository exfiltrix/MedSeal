// The ?next= target after sign-in: only a path on this site (never "//evil.example" or a full URL,
// which would turn the login page into an open redirect).
export function safeNext(fallback = "/"): string {
  if (typeof window === "undefined") return fallback;
  const next = new URLSearchParams(window.location.search).get("next") ?? "";
  return next.startsWith("/") && !next.startsWith("//") && !next.startsWith("/\\") ? next : fallback;
}

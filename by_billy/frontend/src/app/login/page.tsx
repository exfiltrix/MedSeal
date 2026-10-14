"use client";

import { useState, type FormEvent } from "react";
import PageShell from "@/components/PageShell";
import { Button, Card, ErrorBox, Spinner, errorMessage } from "@/components/ui";
import { useLanguage } from "@/lib/language-context";
import dictionary from "@/lib/dictionary";
import { safeNext } from "@/lib/nextPath";
import { sessionApi } from "@/lib/sessionApi";

const d = dictionary.auth;
const input =
  "mt-1 w-full rounded-xl border border-border bg-white px-3 py-2.5 text-sm outline-none focus:border-accent focus:ring-2 focus:ring-accent/20";

export default function LoginPage() {
  const { t } = useLanguage();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [totp, setTotp] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const { user } = await sessionApi.login(username, password, totp);
      const next = safeNext("/");
       
      window.location.assign(user.must_change_password ? `/account?next=${encodeURIComponent(next)}` : next);
    } catch (err) {
      setError(errorMessage(err));
      setPassword("");
      setTotp("");
      setBusy(false);
    }
  };

  return (
    <PageShell title={t(d.title)} subtitle={t(d.subtitle)}>
      <Card className="mx-auto max-w-md">
        <form onSubmit={submit} className="space-y-4">
          <label className="block text-sm font-medium">
            {t(d.username)}
            <input className={input} autoComplete="username" required value={username} onChange={(e) => setUsername(e.target.value)} />
          </label>
          <label className="block text-sm font-medium">
            {t(d.password)}
            <input className={input} type="password" autoComplete="current-password" required value={password} onChange={(e) => setPassword(e.target.value)} />
          </label>
          <label className="block text-sm font-medium">
            {t(d.totp)}
            <input
              className={input}
              inputMode="numeric"
              autoComplete="one-time-code"
              pattern="[0-9]{6}"
              maxLength={6}
              value={totp}
              onChange={(e) => setTotp(e.target.value.replace(/\D/g, ""))}
            />
            <span className="mt-1 block text-xs font-normal text-muted">{t(d.totpHint)}</span>
          </label>
          {error && <ErrorBox message={error} />}
          <Button type="submit" variant="dark" disabled={busy} className="w-full">
            {busy && <Spinner />} {t(d.submit)}
          </Button>
        </form>
      </Card>
    </PageShell>
  );
}

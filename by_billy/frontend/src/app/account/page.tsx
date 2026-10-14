"use client";

import { useEffect, useState, type FormEvent } from "react";
import PageShell from "@/components/PageShell";
import { Button, Card, ErrorBox, Field, Spinner, errorMessage } from "@/components/ui";
import { useLanguage } from "@/lib/language-context";
import dictionary from "@/lib/dictionary";
import { safeNext } from "@/lib/nextPath";
import { redirectForAuth, sessionApi, type Me } from "@/lib/sessionApi";

const d = dictionary.auth;
const input =
  "mt-1 w-full rounded-xl border border-border bg-white px-3 py-2.5 text-sm outline-none focus:border-accent focus:ring-2 focus:ring-accent/20";

export default function AccountPage() {
  const { t } = useLanguage();
  const [me, setMe] = useState<Me | null>(null);
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [repeat, setRepeat] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [saved, setSaved] = useState(false);

  useEffect(() => {
    sessionApi.me().then(setMe).catch((e) => redirectForAuth(e) || setError(errorMessage(e)));
  }, []);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    if (next !== repeat) {
      setError(t(d.mismatch));
      return;
    }
    setBusy(true);
    try {
      const updated = await sessionApi.changePassword(current, next);
      setMe(updated);
      setSaved(true);
      setCurrent("");
      setNext("");
      setRepeat("");
      const target = safeNext("");
       
      if (target) window.location.assign(target);
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  const signOut = async () => {
    await sessionApi.logout().catch(() => undefined);
    // eslint-disable-next-line @next/next/no-location-assign-relative-destination -- full reload on purpose: no data of the previous session may stay in memory
    window.location.assign("/login");
  };

  return (
    <PageShell title={t(dictionary.nav.account)}>
      <div className="mx-auto max-w-md space-y-5">
        {me && (
          <Card className="grid grid-cols-2 gap-4">
            <Field label={t(d.signedInAs)} value={me.full_name || me.username} />
            <Field label={t(dictionary.users.role)} value={t(dictionary.users.roles[me.role])} />
            {me.hospital && <Field label={t(dictionary.users.hospital)} value={me.hospital} />}
            <div className="col-span-2">
              <Button variant="ghost" onClick={signOut}>
                {t(dictionary.nav.signOut)}
              </Button>
            </div>
          </Card>
        )}
        <Card>
          <h2 className="text-lg font-semibold">{t(d.changePassword)}</h2>
          {me?.must_change_password && <p className="mt-2 text-sm text-amber-800">{t(d.mustChange)}</p>}
          <form onSubmit={submit} className="mt-4 space-y-4">
            <label className="block text-sm font-medium">
              {t(d.currentPassword)}
              <input className={input} type="password" autoComplete="current-password" required value={current} onChange={(e) => setCurrent(e.target.value)} />
            </label>
            <label className="block text-sm font-medium">
              {t(d.newPassword)}
              <input className={input} type="password" autoComplete="new-password" minLength={12} required value={next} onChange={(e) => setNext(e.target.value)} />
            </label>
            <label className="block text-sm font-medium">
              {t(d.repeatPassword)}
              <input className={input} type="password" autoComplete="new-password" minLength={12} required value={repeat} onChange={(e) => setRepeat(e.target.value)} />
            </label>
            {error && <ErrorBox message={error} />}
            {saved && (
              <p role="status" className="text-sm text-ok">
                {t(d.saved)}. {t(d.otherSessions)}
              </p>
            )}
            <Button type="submit" disabled={busy}>
              {busy && <Spinner />} {t(d.changePassword)}
            </Button>
          </form>
        </Card>
      </div>
    </PageShell>
  );
}

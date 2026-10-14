"use client";

import { useCallback, useEffect, useState, type FormEvent } from "react";
import PageShell from "@/components/PageShell";
import { Button, Card, ErrorBox, Spinner, errorMessage } from "@/components/ui";
import { useLanguage } from "@/lib/language-context";
import dictionary from "@/lib/dictionary";
import { redirectForAuth, sessionApi, type Me, type Role } from "@/lib/sessionApi";

const d = dictionary.users;
const ROLES: Role[] = ["doctor", "operator", "auditor", "client", "admin"];
const input =
  "mt-1 w-full rounded-xl border border-border bg-white px-3 py-2 text-sm outline-none focus:border-accent focus:ring-2 focus:ring-accent/20";

export default function UsersPage() {
  const { t } = useLanguage();
  const [users, setUsers] = useState<Me[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [mfaUri, setMfaUri] = useState<string | null>(null);
  const [form, setForm] = useState({ username: "", full_name: "", role: "doctor" as Role, hospital: "", password: "" });
  const [busy, setBusy] = useState(false);

  const load = useCallback(() => {
    sessionApi.users().then(setUsers).catch((e) => redirectForAuth(e) || setError(errorMessage(e)));
  }, []);
  useEffect(load, [load]);

  const create = async (e: FormEvent) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setMfaUri(null);
    try {
      const created = await sessionApi.createUser(form);
      setMfaUri(created.mfa_provisioning_uri ?? null);
      setForm({ username: "", full_name: "", role: "doctor", hospital: "", password: "" });
      load();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  const act = async (fn: () => Promise<{ mfa_provisioning_uri?: string }>) => {
    setError(null);
    setMfaUri(null);
    try {
      const r = await fn();
      setMfaUri(r.mfa_provisioning_uri ?? null);
      load();
    } catch (err) {
      setError(errorMessage(err));
    }
  };

  const reset = (u: Me) => {
    const password = window.prompt(`${t(d.tempPassword)} — ${u.username}`);
    if (!password) return;
    const withMfa = u.role === "admin" && window.confirm(t(d.resetMfa));
    act(() => sessionApi.reset(u.id, password, withMfa));
  };

  return (
    <PageShell title={t(d.title)} subtitle={t(d.subtitle)}>
      <div className="space-y-5">
        {error && <ErrorBox message={error} />}
        {mfaUri && (
          <Card className="border-amber-300 bg-amber-50">
            <p className="text-sm font-medium text-amber-900">{t(d.mfaOnce)}</p>
            <p className="mt-2 break-all font-mono text-xs">{mfaUri}</p>
          </Card>
        )}

        <Card>
          <h2 className="text-lg font-semibold">{t(d.create)}</h2>
          <form onSubmit={create} className="mt-4 grid gap-3 sm:grid-cols-2">
            <label className="text-sm font-medium">
              {t(dictionary.auth.username)}
              <input className={input} required value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} />
            </label>
            <label className="text-sm font-medium">
              {t(d.fullName)}
              <input className={input} value={form.full_name} onChange={(e) => setForm({ ...form, full_name: e.target.value })} />
            </label>
            <label className="text-sm font-medium">
              {t(d.role)}
              <select className={input} value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value as Role })}>
                {ROLES.map((r) => (
                  <option key={r} value={r}>
                    {t(d.roles[r])}
                  </option>
                ))}
              </select>
            </label>
            <label className="text-sm font-medium">
              {t(d.hospital)}
              <input className={input} required={form.role === "client"} value={form.hospital} onChange={(e) => setForm({ ...form, hospital: e.target.value })} />
            </label>
            <label className="text-sm font-medium sm:col-span-2">
              {t(d.tempPassword)}
              <input className={input} type="password" autoComplete="new-password" minLength={12} required value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
            </label>
            <div className="sm:col-span-2">
              <Button type="submit" disabled={busy}>
                {busy && <Spinner />} {t(d.create)}
              </Button>
            </div>
          </form>
        </Card>

        <Card className="overflow-x-auto">
          {!users ? (
            <Spinner />
          ) : (
            <table className="w-full text-left text-sm">
              <thead className="text-xs text-muted">
                <tr>
                  <th className="py-2 pr-3">{t(dictionary.auth.username)}</th>
                  <th className="py-2 pr-3">{t(d.fullName)}</th>
                  <th className="py-2 pr-3">{t(d.role)}</th>
                  <th className="py-2 pr-3">{t(d.hospital)}</th>
                  <th className="py-2 pr-3" />
                  <th className="py-2" />
                </tr>
              </thead>
              <tbody>
                {users.map((u) => (
                  <tr key={u.id} className="border-t border-border">
                    <td className="py-2 pr-3 font-mono">{u.username}</td>
                    <td className="py-2 pr-3">{u.full_name}</td>
                    <td className="py-2 pr-3">{t(d.roles[u.role])}</td>
                    <td className="py-2 pr-3">{u.hospital}</td>
                    <td className="py-2 pr-3">{u.active ? t(d.active) : t(d.inactive)}</td>
                    <td className="flex gap-2 py-2">
                      <Button variant="ghost" onClick={() => reset(u)}>
                        {t(d.reset)}
                      </Button>
                      {u.active && (
                        <Button variant="ghost" onClick={() => act(async () => (await sessionApi.deactivate(u.id), {}))}>
                          {t(d.deactivate)}
                        </Button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      </div>
    </PageShell>
  );
}

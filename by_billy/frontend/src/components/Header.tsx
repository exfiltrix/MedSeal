"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useLanguage } from "@/lib/language-context";
import dictionary from "@/lib/dictionary";
import { api } from "@/lib/api";
import { sessionApi, type Me } from "@/lib/sessionApi";
import LanguageSwitch from "./LanguageSwitch";
import AccessibilityPanel from "./AccessibilityPanel";
import { ChartIcon, CrashTestIcon, InboxIcon, PassportIcon, PriceTagIcon, SealIcon, VerifyIcon } from "./icons";

const LINKS = [
  { href: "/inbox", key: "inbox", icon: InboxIcon },
  { href: "/client", key: "client", icon: PassportIcon },
  { href: "/seal", key: "seal", icon: SealIcon },
  { href: "/verify", key: "verify", icon: VerifyIcon },
  { href: "/crash-test", key: "crashTest", icon: CrashTestIcon, match: ["/crash-test", "/passport"] },
  { href: "/dashboard", key: "dashboard", icon: ChartIcon },
  { href: "/pricing", key: "pricing", icon: PriceTagIcon },
] as const;

// The signed-in person, if any (src/lib/sessionApi.ts). The cookie is httpOnly, so asking the
// server is the only way to know; a 401 simply means "not signed in" and is not an error here.
function useMe(): Me | null {
  const [me, setMe] = useState<Me | null>(null);
  useEffect(() => {
    sessionApi.me().then(setMe).catch(() => setMe(null));
  }, []);
  return me;
}

// Unread-alert badge: only for someone who can read the inbox, so no other page ever polls it.
function useUnreadCount(pathname: string, me: Me | null): number | null {
  const [count, setCount] = useState<number | null>(null);
  const canRead = !!me && !me.must_change_password && (me.role === "doctor" || me.role === "admin");
  useEffect(() => {
    if (!canRead) return;
    let cancelled = false;
    const poll = () => {
      api
        .getInbox({ limit: 1 })
        .then((listing) => {
          if (!cancelled) setCount(listing.counts.danger + listing.counts.warning);
        })
        .catch(() => undefined);
    };
    poll();
    const timer = setInterval(poll, 15000);
    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [pathname, canRead]);
  return count;
}

export default function Header() {
  const { t } = useLanguage();
  const pathname = usePathname();
  const me = useMe();
  const unread = useUnreadCount(pathname, me);
  const signOut = async () => {
    await sessionApi.logout().catch(() => undefined);
    // eslint-disable-next-line @next/next/no-location-assign-relative-destination -- full reload on purpose: no data of the previous session may stay in memory
    window.location.assign("/login");
  };
  const isActive = (l: (typeof LINKS)[number]) =>
    ("match" in l ? l.match : [l.href]).some((p) => pathname.startsWith(p));
  const linkClass = (active: boolean) =>
    `flex items-center gap-1.5 whitespace-nowrap rounded-full px-3.5 py-2 transition-colors ${
      active ? "bg-white text-foreground shadow-sm" : "text-muted hover:bg-white/60 hover:text-foreground"
    }`;

  return (
    <header className="sticky top-0 z-20 border-b border-white/60 bg-background/70 backdrop-blur-xl print:hidden">
      <div className="mx-auto flex max-w-6xl flex-wrap items-center justify-between gap-3 px-4 py-3 sm:px-6">
        <Link href="/" className="flex items-center gap-2">
          <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-foreground text-white">
            <SealIcon width={18} height={18} />
          </span>
          <span className="text-lg font-semibold tracking-tight">MedSeal</span>
        </Link>

        <nav aria-label={t(dictionary.nav.menu)} className="hidden items-center gap-1 rounded-full border border-white/70 bg-white/40 p-1 text-sm font-medium md:flex">
          {LINKS.map((l) => {
            const Icon = l.icon;
            const active = isActive(l);
            return (
              <Link key={l.href} href={l.href} className={linkClass(active)} aria-current={active ? "page" : undefined}>
                <Icon width={16} height={16} />
                {t(dictionary.nav[l.key])}
                {l.key === "inbox" && !!unread && (
                  <span
                    aria-label={t(dictionary.inbox.unreadAlerts).replace("{n}", String(unread))}
                    className="flex h-4 min-w-4 items-center justify-center rounded-full bg-danger px-1 text-[10px] font-semibold text-white"
                  >
                    {unread}
                  </span>
                )}
              </Link>
            );
          })}
        </nav>

        <div className="flex items-center gap-2">
          <AccessibilityPanel />
          <LanguageSwitch />
          {me ? (
            <div className="flex items-center gap-1 text-sm">
              {me.role === "admin" && (
                <Link href="/admin/users" className="rounded-full px-3 py-1.5 font-medium hover:bg-white/70">
                  {t(dictionary.nav.admin)}
                </Link>
              )}
              <Link href="/account" className="rounded-full px-3 py-1.5 font-medium hover:bg-white/70" title={t(dictionary.nav.account)}>
                {me.username}
              </Link>
              <button onClick={signOut} className="rounded-full px-3 py-1.5 text-muted hover:bg-white/70 hover:text-foreground">
                {t(dictionary.nav.signOut)}
              </button>
            </div>
          ) : (
            <Link href="/login" className="rounded-full bg-foreground px-4 py-1.5 text-sm font-medium text-white">
              {t(dictionary.nav.signIn)}
            </Link>
          )}
        </div>
      </div>

      <nav aria-label={t(dictionary.nav.menu)} className="flex gap-1 overflow-x-auto px-3 pb-2.5 text-sm font-medium md:hidden">
        {LINKS.map((l) => {
          const Icon = l.icon;
          const active = isActive(l);
          return (
            <Link key={l.href} href={l.href} className={linkClass(active)} aria-current={active ? "page" : undefined}>
              <Icon width={16} height={16} />
              {t(dictionary.nav[l.key])}
              {l.key === "inbox" && !!unread && (
                <span
                  aria-label={t(dictionary.inbox.unreadAlerts).replace("{n}", String(unread))}
                  className="flex h-4 min-w-4 items-center justify-center rounded-full bg-danger px-1 text-[10px] font-semibold text-white"
                >
                  {unread}
                </span>
              )}
            </Link>
          );
        })}
      </nav>
    </header>
  );
}

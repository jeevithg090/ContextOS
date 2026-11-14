import { useCallback, useEffect, useRef, useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";
import { LogOut, Menu, PanelLeftClose } from "lucide-react";
import { NAV, type NavItem } from "@/app/nav";
import { useAuth } from "@/features/auth/AuthProvider";
import { useNavCounts } from "@/features/overview/api";
import type { NavCounts } from "@/features/overview/types";
import { useLiveEvents } from "@/hooks/useLiveEvents";
import { cn } from "@/lib/format";
import { IconButton, StatusDot, Tooltip } from "@/components/ui";
import { ThemeMenu } from "./ThemeMenu";

const BADGE_FIELD: Record<NonNullable<NavItem["badgeKey"]>, keyof NavCounts> = {
  pendingApprovals: "pending_approvals",
  openIncidents: "open_incidents",
  openFindings: "open_findings",
};

function Logo() {
  return (
    <div className="flex items-center gap-2.5 px-3">
      <svg viewBox="0 0 32 32" className="h-6 w-6" aria-hidden>
        <path d="M9 11.5 16 7l7 4.5v9L16 25l-7-4.5z" fill="none" stroke="rgb(var(--accent))" strokeWidth="2.2" strokeLinejoin="round" />
        <circle cx="16" cy="16" r="2.6" fill="rgb(var(--accent))" />
      </svg>
      <span className="text-[14px] font-semibold tracking-tight text-fg">ContextOS</span>
    </div>
  );
}

function Sidebar({ onNavigate }: { onNavigate?: () => void }) {
  const counts = useNavCounts().data;
  const badge = (key?: NavItem["badgeKey"]) => (counts && key ? counts[BADGE_FIELD[key]] ?? 0 : 0);
  return (
    <nav className="flex h-full flex-col gap-5 overflow-y-auto pb-6 pt-4" aria-label="Main">
      <Logo />
      {NAV.map((section) => (
        <div key={section.title}>
          <div className="label-caps mb-1 px-5">{section.title}</div>
          <ul className="space-y-px px-2">
            {section.items.map((item) => {
              const count = badge(item.badgeKey);
              return (
                <li key={item.to}>
                  <NavLink
                    to={item.to}
                    end={item.to === "/"}
                    onClick={onNavigate}
                    title={item.question}
                    className={({ isActive }) =>
                      cn(
                        "group flex h-8 items-center gap-2.5 rounded px-3 text-[13px] transition-colors touch:h-10",
                        isActive ? "bg-surface-3 text-fg" : "text-fg-muted hover:bg-surface-2 hover:text-fg",
                      )
                    }
                  >
                    {({ isActive }) => (
                      <>
                        <item.icon className={cn("h-4 w-4 shrink-0", isActive ? "text-accent" : "text-fg-faint group-hover:text-fg-muted")} aria-hidden />
                        <span className="truncate">{item.label}</span>
                        {count > 0 && (
                          <span className="num ml-auto rounded bg-surface-3 px-1.5 text-2xs font-medium text-fg-muted group-hover:bg-surface">
                            <span className="sr-only">(</span>
                            {count}
                            <span className="sr-only">)</span>
                          </span>
                        )}
                      </>
                    )}
                  </NavLink>
                </li>
              );
            })}
          </ul>
        </div>
      ))}
    </nav>
  );
}

function LiveIndicator({ status }: { status: "connecting" | "live" | "offline" }) {
  const label = status === "live" ? "Live" : status === "connecting" ? "Connecting" : "Offline — retrying";
  return (
    <Tooltip content={status === "live" ? "Receiving live security events" : "Live stream unavailable; data refreshes periodically"}>
      <span className="inline-flex items-center gap-1.5 text-xs text-fg-muted">
        <StatusDot tone={status === "live" ? "ok" : status === "connecting" ? "warn" : "neutral"} pulse={status === "live"} />
        {label}
      </span>
    </Tooltip>
  );
}

/**
 * Navigation drawer below lg: a modal dialog that takes focus, closes on Escape or a backdrop tap,
 * keeps Tab inside itself and hands focus back to the menu button when it closes.
 */
function MobileNav({ onClose }: { onClose: () => void }) {
  const panel = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const opener = document.activeElement as HTMLElement | null;
    panel.current?.querySelector<HTMLElement>("button")?.focus();
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        e.preventDefault();
        onClose();
        return;
      }
      if (e.key !== "Tab" || !panel.current) return;
      const focusable = panel.current.querySelectorAll<HTMLElement>("a[href], button:not([disabled])");
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last?.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first?.focus();
      }
    };
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("keydown", onKey);
      opener?.focus?.();
    };
  }, [onClose]);
  return (
    <div className="fixed inset-0 z-40 lg:hidden">
      <div className="absolute inset-0 bg-scrim/60 animate-fade-in" onClick={onClose} aria-hidden />
      <div ref={panel} role="dialog" aria-modal="true" aria-label="Navigation" className="absolute inset-y-0 left-0 w-64 max-w-[85vw] border-r border-border bg-surface shadow-pop animate-slide-in-right">
        <div className="flex justify-end p-2">
          <IconButton label="Close navigation" onClick={onClose}>
            <PanelLeftClose className="h-4 w-4" />
          </IconButton>
        </div>
        <Sidebar onNavigate={onClose} />
      </div>
    </div>
  );
}

export function AppShell() {
  const { me, logout } = useAuth();
  const live = useLiveEvents(!!me);
  const [mobileOpen, setMobileOpen] = useState(false);
  const closeMobileNav = useCallback(() => setMobileOpen(false), []);
  const location = useLocation();

  return (
    <div className="flex h-full">
      <a
        href="#main-content"
        className="sr-only z-50 rounded bg-accent px-3 py-1.5 text-xs font-medium text-accent-fg focus:not-sr-only focus:fixed focus:left-3 focus:top-2"
      >
        Skip to content
      </a>
      <aside className="hidden w-60 shrink-0 border-r border-border bg-surface/60 lg:block">
        <Sidebar />
      </aside>
      {mobileOpen && <MobileNav onClose={closeMobileNav} />}
      <div className="flex min-w-0 flex-1 flex-col">
        <header className="flex h-12 shrink-0 items-center gap-3 border-b border-border px-4">
          <IconButton label="Open navigation" className="lg:hidden" onClick={() => setMobileOpen(true)}>
            <Menu className="h-4 w-4" />
          </IconButton>
          <div className="flex min-w-0 items-center gap-2 text-[13px]">
            <span className="truncate font-medium text-fg">{me?.organization.name}</span>
            <span className="text-fg-faint">/</span>
            <span className="truncate text-fg-muted">{me?.role?.replace("_", " ")}</span>
          </div>
          <div className="ml-auto flex items-center gap-2 sm:gap-3">
            <LiveIndicator status={live} />
            <div className="hidden text-xs text-fg-muted md:block">{me?.user.email}</div>
            <ThemeMenu />
            <IconButton label="Sign out" onClick={() => void logout()}>
              <LogOut className="h-4 w-4" />
            </IconButton>
          </div>
        </header>
        <main id="main-content" tabIndex={-1} className="relative min-h-0 flex-1 overflow-y-auto focus:outline-none">
          {/* Each route renders inside its own Suspense and error boundary (src/app/routes.tsx). */}
          {/* `relative` on <main>: absolutely positioned descendants without a positioned ancestor (e.g. sr-only
              live regions) would otherwise be placed against the document and make the whole page scroll. */}
          <div key={location.pathname} className="mx-auto w-full max-w-[1480px] px-4 py-6 sm:px-6 animate-fade-in">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}

/**
 * Colour theme: "dark" (the default look), "light", or "system" (follow the OS setting).
 *
 * The resolved theme is written to <html data-theme> (the light tokens in src/styles/index.css key
 * off it) and mirrored as the `dark` class. index.html applies the stored choice before the first
 * paint so a light-theme user never sees a dark flash; this module keeps it in sync afterwards.
 */
import { useCallback, useEffect, useSyncExternalStore } from "react";

export type ThemePreference = "system" | "light" | "dark";
export type ResolvedTheme = "light" | "dark";

export const THEME_STORAGE_KEY = "contextos.theme";
const THEME_COLORS: Record<ResolvedTheme, string> = { dark: "#090b0e", light: "#f6f7f9" };
const PREFERENCES: ThemePreference[] = ["system", "light", "dark"];

const listeners = new Set<() => void>();

function readPreference(): ThemePreference {
  try {
    const stored = window.localStorage.getItem(THEME_STORAGE_KEY);
    if (stored && (PREFERENCES as string[]).includes(stored)) return stored as ThemePreference;
  } catch {
    /* storage unavailable (private mode, blocked cookies): fall back to the default */
  }
  return "dark";
}

function systemTheme(): ResolvedTheme {
  return typeof window.matchMedia === "function" && window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

export function resolveTheme(preference: ThemePreference): ResolvedTheme {
  return preference === "system" ? systemTheme() : preference;
}

/** Apply a resolved theme to the document; `animate` cross-fades colours for a user-initiated switch. */
export function applyTheme(theme: ResolvedTheme, animate = false) {
  const root = document.documentElement;
  if (animate) root.classList.add("theme-switching");
  root.dataset.theme = theme;
  root.classList.toggle("dark", theme === "dark");
  document.querySelector('meta[name="theme-color"]')?.setAttribute("content", THEME_COLORS[theme]);
  if (animate) window.setTimeout(() => root.classList.remove("theme-switching"), 200);
}

let preference: ThemePreference = typeof window === "undefined" ? "dark" : readPreference();

function emit() {
  listeners.forEach((listener) => listener());
}

export function setThemePreference(next: ThemePreference) {
  preference = next;
  try {
    window.localStorage.setItem(THEME_STORAGE_KEY, next);
  } catch {
    /* not persisted; the choice still applies for this visit */
  }
  applyTheme(resolveTheme(next), true);
  emit();
}

function subscribe(listener: () => void) {
  listeners.add(listener);
  return () => listeners.delete(listener);
}

/** Current preference and resolved theme, re-rendering when either changes (including OS changes). */
export function useTheme() {
  // The snapshot carries the resolved theme too, so an OS change re-renders "system" users.
  const snapshot = useSyncExternalStore(subscribe, () => `${preference}|${resolveTheme(preference)}`, () => "dark|dark");
  const [pref, resolved] = snapshot.split("|") as [ThemePreference, ResolvedTheme];

  useEffect(() => {
    if (pref !== "system" || typeof window.matchMedia !== "function") return;
    const query = window.matchMedia("(prefers-color-scheme: light)");
    const onChange = () => {
      applyTheme(systemTheme(), true);
      emit();
    };
    query.addEventListener?.("change", onChange);
    return () => query.removeEventListener?.("change", onChange);
  }, [pref]);

  const cycle = useCallback(() => {
    setThemePreference(PREFERENCES[(PREFERENCES.indexOf(pref) + 1) % PREFERENCES.length]);
  }, [pref]);

  return { preference: pref, resolved, setPreference: setThemePreference, cycle };
}

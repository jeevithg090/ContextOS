import { act, renderHook } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { applyTheme, resolveTheme, setThemePreference, THEME_STORAGE_KEY, useTheme } from "../theme";

function stubSystemTheme(light: boolean) {
  vi.stubGlobal("matchMedia", (query: string) => ({
    matches: light && query.includes("light"),
    media: query,
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
  }));
}

afterEach(() => {
  vi.unstubAllGlobals();
  window.localStorage.clear();
  act(() => setThemePreference("dark"));
});

describe("theme", () => {
  it("resolves 'system' from the OS preference", () => {
    stubSystemTheme(true);
    expect(resolveTheme("system")).toBe("light");
    stubSystemTheme(false);
    expect(resolveTheme("system")).toBe("dark");
    expect(resolveTheme("light")).toBe("light");
  });

  it("writes the theme to <html> and the theme-color meta tag", () => {
    const meta = document.createElement("meta");
    meta.name = "theme-color";
    document.head.appendChild(meta);
    applyTheme("light");
    expect(document.documentElement.dataset.theme).toBe("light");
    expect(document.documentElement.classList.contains("dark")).toBe(false);
    expect(meta.content).toBe("#f6f7f9");
    applyTheme("dark");
    expect(document.documentElement.classList.contains("dark")).toBe(true);
    meta.remove();
  });

  it("persists the choice and re-renders subscribers", () => {
    stubSystemTheme(false);
    const { result } = renderHook(() => useTheme());
    expect(result.current.preference).toBe("dark");
    act(() => result.current.setPreference("light"));
    expect(result.current).toMatchObject({ preference: "light", resolved: "light" });
    expect(window.localStorage.getItem(THEME_STORAGE_KEY)).toBe("light");
    expect(document.documentElement.dataset.theme).toBe("light");
    act(() => result.current.cycle());
    expect(result.current).toMatchObject({ preference: "dark", resolved: "dark" });
  });
});

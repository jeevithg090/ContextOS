/** ContextOS design tokens. Colours are CSS variables (see src/styles/index.css) so status
 * semantics stay consistent everywhere. Use semantic names (bg-surface, text-muted, trust-*,
 * sev-*, dec-*) — never raw Tailwind palette colours in feature code. */
const v = (name) => `rgb(var(--${name}) / <alpha-value>)`;

export default {
  darkMode: "class",
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: v("bg"),
        surface: { DEFAULT: v("surface"), 2: v("surface-2"), 3: v("surface-3") },
        border: { DEFAULT: v("border"), strong: v("border-strong") },
        fg: { DEFAULT: v("fg"), muted: v("fg-muted"), faint: v("fg-faint") },
        accent: { DEFAULT: v("accent"), strong: v("accent-strong"), fg: v("accent-fg") },
        trust: {
          trusted: v("trust-trusted"),
          approved: v("trust-approved"),
          external: v("trust-external"),
          unknown: v("trust-unknown"),
          suspicious: v("trust-suspicious"),
          blocked: v("trust-blocked"),
        },
        sev: {
          critical: v("sev-critical"),
          high: v("sev-high"),
          medium: v("sev-medium"),
          low: v("sev-low"),
          info: v("sev-info"),
        },
        dec: {
          allow: v("dec-allow"),
          deny: v("dec-deny"),
          approval: v("dec-approval"),
          restrict: v("dec-restrict"),
          audit: v("dec-audit"),
        },
        ok: v("ok"),
        warn: v("warn"),
        danger: v("danger"),
        // Backdrop behind dialogs, drawers and the mobile navigation.
        scrim: v("scrim"),
      },
      fontFamily: {
        sans: ["'Inter Variable'", "Inter", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ["'JetBrains Mono'", "ui-monospace", "SFMono-Regular", "Menlo", "monospace"],
      },
      fontSize: {
        "2xs": ["0.6875rem", { lineHeight: "1rem" }],
      },
      borderRadius: { DEFAULT: "6px", md: "8px", lg: "10px", xl: "14px" },
      boxShadow: {
        panel: "var(--shadow-panel)",
        pop: "var(--shadow-pop)",
      },
      keyframes: {
        "fade-in": { from: { opacity: 0 }, to: { opacity: 1 } },
        "slide-in-right": { from: { transform: "translateX(16px)", opacity: 0 }, to: { transform: "none", opacity: 1 } },
        "slide-up": { from: { transform: "translateY(4px)", opacity: 0 }, to: { transform: "none", opacity: 1 } },
        // Dialogs are centred with translateX(-50%); the entrance keeps that translate so the panel
        // does not jump sideways while animating.
        "dialog-in": { from: { transform: "translate(-50%, 4px)", opacity: 0 }, to: { transform: "translate(-50%, 0)", opacity: 1 } },
        pulse_dot: { "0%,100%": { opacity: 1 }, "50%": { opacity: 0.35 } },
      },
      animation: {
        "fade-in": "fade-in 160ms ease-out",
        "slide-in-right": "slide-in-right 200ms cubic-bezier(.2,.8,.2,1)",
        "slide-up": "slide-up 160ms ease-out",
        "dialog-in": "dialog-in 160ms ease-out",
        "pulse-dot": "pulse_dot 1.6s ease-in-out infinite",
      },
    },
  },
  plugins: [
    // `touch:` applies on coarse pointers (phones, tablets) — used to grow small controls to a
    // comfortable tap size without changing the dense desktop layout.
    ({ addVariant }) => addVariant("touch", "@media (pointer: coarse)"),
  ],
};

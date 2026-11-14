import { defineConfig, type UserConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";

/**
 * Vendor chunks. Pages are already split per route (src/app/routes.tsx); these groups keep large
 * libraries in their own long-lived files so an app release does not invalidate them, and so a
 * page only downloads the heavy library it uses (the provenance graph never loads the chart code).
 * Modules shared by two groups (lodash, d3-color/d3-interpolate) get their own chunk instead of
 * making one group import the other.
 */
const VENDOR_CHUNKS: Array<[name: string, packages: string[]]> = [
  ["vendor-react", ["react", "react-dom", "scheduler", "react-router", "react-router-dom", "cookie", "set-cookie-parser"]],
  ["vendor-query", ["@tanstack/react-query", "@tanstack/query-core"]],
  [
    "vendor-radix",
    ["@radix-ui", "@floating-ui", "react-remove-scroll", "react-remove-scroll-bar", "react-style-singleton", "use-callback-ref", "use-sidecar", "aria-hidden", "get-nonce", "tslib"],
  ],
  ["vendor-date", ["date-fns"]],
  ["vendor-flow", ["@xyflow", "zustand", "classcat", "use-sync-external-store", "d3-drag", "d3-selection", "d3-zoom", "d3-transition", "d3-dispatch", "d3-ease", "d3-timer"]],
  ["vendor-dagre", ["dagre", "graphlib"]],
  [
    "vendor-charts",
    [
      "recharts", "recharts-scale", "react-smooth", "victory-vendor", "d3-array", "d3-format", "d3-path", "d3-scale", "d3-shape",
      "d3-time", "d3-time-format", "internmap", "decimal.js-light", "eventemitter3", "fast-equals", "tiny-invariant", "prop-types",
      "react-is", "react-transition-group", "dom-helpers",
    ],
  ],
  ["vendor-d3-common", ["d3-color", "d3-interpolate"]],
  ["vendor-lodash", ["lodash"]],
  ["vendor-dnd", ["@dnd-kit"]],
];

function packageOf(id: string): string | null {
  const at = id.lastIndexOf("/node_modules/");
  if (at < 0) return null;
  const parts = id.slice(at + "/node_modules/".length).split("/");
  return parts[0].startsWith("@") ? `${parts[0]}/${parts[1]}` : parts[0];
}

export function vendorChunk(id: string): string | undefined {
  const pkg = packageOf(id.replace(/\\/g, "/"));
  if (!pkg) return undefined;
  for (const [name, packages] of VENDOR_CHUNKS) {
    if (packages.some((p) => pkg === p || (p.startsWith("@") && !p.includes("/") && pkg.startsWith(`${p}/`)))) return name;
  }
  return undefined;
}

export default defineConfig({
  plugins: [react()],
  resolve: { alias: { "@": path.resolve(__dirname, "src") } },
  server: {
    port: 5173,
    proxy: { "/api": { target: "http://127.0.0.1:8000", changeOrigin: false } },
  },
  build: {
    outDir: "dist",
    sourcemap: true,
    // Vite's default warning threshold (500 kB minified); no chunk should exceed it.
    chunkSizeWarningLimit: 500,
    rollupOptions: { output: { manualChunks: vendorChunk } },
  },
  // Vitest reads `test`; it bundles its own Vite, so its typed defineConfig does not accept this
  // project's Vite plugins — hence the assertion instead of vitest/config.
  test: { environment: "jsdom", globals: true, setupFiles: ["./src/test/setup.ts"] },
} as UserConfig);

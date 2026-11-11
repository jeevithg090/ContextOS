/**
 * `cn()` — join class names and resolve Tailwind conflicts so the LAST class of a group wins.
 *
 * Tailwind emits utilities in a fixed stylesheet order, not in the order they appear in
 * `className`, so `cn("h-8", "h-7")` would otherwise render at h-8 (h-8 is later in the CSS) and a
 * component's `className` prop could not override its built-in size, padding or colour. This is
 * a deliberately small, dependency-free subset of tailwind-merge covering the utility groups the
 * design system actually overrides: sizing, spacing, text size/colour/alignment, font weight and
 * family, background and border colour, display, position, flex alignment, overflow and z-index.
 *
 * Conflicts are scoped by variant ("hover:", "sm:", "data-[state=open]:") and by the important
 * modifier ("!"), exactly like Tailwind: `hover:h-7` never removes `h-8`. Classes outside the known
 * groups (custom component classes such as `panel`, unknown utilities) are always kept.
 */

type Group = string;

/** Groups that a class of the key group also overrides (a later `p-2` replaces an earlier `px-3`). */
const OVERRIDES: Record<Group, Group[]> = {
  p: ["px", "py", "pt", "pr", "pb", "pl", "ps", "pe"],
  px: ["pl", "pr", "ps", "pe"],
  py: ["pt", "pb"],
  m: ["mx", "my", "mt", "mr", "mb", "ml", "ms", "me"],
  mx: ["ml", "mr", "ms", "me"],
  my: ["mt", "mb"],
  size: ["w", "h"],
  gap: ["gap-x", "gap-y"],
  overflow: ["overflow-x", "overflow-y"],
  "border-color": ["border-color-x", "border-color-y", "border-color-t", "border-color-r", "border-color-b", "border-color-l"],
  "border-color-x": ["border-color-l", "border-color-r"],
  "border-color-y": ["border-color-t", "border-color-b"],
};

const DISPLAY = new Set([
  "block", "inline-block", "inline", "flex", "inline-flex", "table", "inline-table", "table-caption", "table-cell",
  "table-column", "table-column-group", "table-footer-group", "table-header-group", "table-row-group", "table-row",
  "flow-root", "grid", "inline-grid", "contents", "list-item", "hidden",
]);
const POSITION = new Set(["static", "fixed", "absolute", "relative", "sticky"]);
const TEXT_SIZES = /^(2xs|xs|sm|base|lg|xl|[2-9]xl)(\/.+)?$/;
const TEXT_ALIGN = /^(left|center|right|justify|start|end)$/;
const TEXT_WRAP = /^(wrap|nowrap|balance|pretty)$/;
const FONT_WEIGHT = /^(thin|extralight|light|normal|medium|semibold|bold|extrabold|black)$/;
const FONT_FAMILY = /^(sans|serif|mono)$/;
const LENGTH = /^\[(length:)?-?(\d*\.)?\d+(px|r?em|%|vh|vw|svh|dvh|ch|ex|pt)?\]$|^\[(length:|calc\(|min\(|max\(|clamp\()/;
const COLOR_ARBITRARY = /^\[(#|rgb|hsl|color:|oklch|var\(--)/;
const BG_NON_COLOR =
  /^(fixed|local|scroll|none|auto|cover|contain|repeat|no-repeat|repeat-x|repeat-y|repeat-round|repeat-space|bottom|center|left|left-bottom|left-top|right|right-bottom|right-top|top)$|^(clip|origin|blend|gradient)-/;
const BORDER_NON_COLOR = /^(\d+|\[\d[^\]]*\]|solid|dashed|dotted|double|hidden|none|collapse|separate)$|^spacing/;
const SPACING = /^(-)?(p|px|py|pt|pr|pb|pl|ps|pe|m|mx|my|mt|mr|mb|ml|ms|me)-(.+)$/;
const SIZING = /^(size|w|h|min-w|min-h|max-w|max-h)-(.+)$/;
const FLEX_ALIGN = /^(items|justify|self|content|place-items|place-content)-(.+)$/;

/** Conflict group of a utility (variants and "!" already removed), or null when unknown. */
function groupOf(utility: string): Group | null {
  if (DISPLAY.has(utility)) return "display";
  if (POSITION.has(utility)) return "position";

  let m = SPACING.exec(utility);
  if (m) return m[2];
  m = SIZING.exec(utility);
  if (m) return m[1];
  m = FLEX_ALIGN.exec(utility);
  if (m) return m[1];

  if (utility.startsWith("gap-x-")) return "gap-x";
  if (utility.startsWith("gap-y-")) return "gap-y";
  if (utility.startsWith("gap-")) return "gap";
  if (/^-?z-/.test(utility)) return "z";
  if (/^overflow-(auto|hidden|clip|visible|scroll)$/.test(utility)) return "overflow";
  if (/^overflow-x-/.test(utility)) return "overflow-x";
  if (/^overflow-y-/.test(utility)) return "overflow-y";
  if (utility.startsWith("leading-")) return "leading";

  if (utility.startsWith("text-")) {
    const v = utility.slice(5);
    if (TEXT_SIZES.test(v) || LENGTH.test(v)) return "text-size";
    if (TEXT_ALIGN.test(v)) return "text-align";
    if (TEXT_WRAP.test(v)) return "text-wrap";
    if (v === "ellipsis" || v === "clip") return "text-overflow";
    if (v.startsWith("[") && !COLOR_ARBITRARY.test(v)) return null;
    return "text-color";
  }
  if (utility.startsWith("font-")) {
    const v = utility.slice(5);
    if (FONT_WEIGHT.test(v)) return "font-weight";
    if (FONT_FAMILY.test(v)) return "font-family";
    return null;
  }
  if (utility.startsWith("bg-")) {
    const v = utility.slice(3);
    if (BG_NON_COLOR.test(v)) return null;
    if (v.startsWith("[") && !COLOR_ARBITRARY.test(v)) return null;
    return "bg-color";
  }
  if (utility.startsWith("border-")) {
    const v = utility.slice(7);
    const side = /^([xytrbl])-(.+)$/.exec(v);
    if (side) return BORDER_NON_COLOR.test(side[2]) ? null : `border-color-${side[1]}`;
    if (/^[xytrblse]$/.test(v) || /^[se]-/.test(v) || BORDER_NON_COLOR.test(v)) return null;
    if (v.startsWith("[") && !COLOR_ARBITRARY.test(v)) return null;
    return "border-color";
  }
  return null;
}

/** Split "sm:hover:!h-7" into ["sm:hover:", "!", "h-7"]; colons inside [...] are not separators. */
function parse(token: string): { variants: string; important: boolean; utility: string } {
  let depth = 0;
  let cut = 0;
  for (let i = 0; i < token.length; i++) {
    const c = token[i];
    if (c === "[") depth++;
    else if (c === "]") depth--;
    else if (c === ":" && depth === 0) cut = i + 1;
  }
  const variants = token.slice(0, cut);
  let utility = token.slice(cut);
  const important = utility.startsWith("!");
  if (important) utility = utility.slice(1);
  return { variants, important, utility };
}

function merge(input: string): string {
  const tokens = input.split(/\s+/).filter(Boolean);
  const taken = new Set<string>();
  const kept: string[] = [];
  for (let i = tokens.length - 1; i >= 0; i--) {
    const token = tokens[i];
    const { variants, important, utility } = parse(token);
    const group = groupOf(utility);
    if (group === null) {
      kept.push(token);
      continue;
    }
    const scope = `${variants}${important ? "!" : ""}`;
    if (taken.has(scope + group)) continue;
    taken.add(scope + group);
    for (const other of OVERRIDES[group] ?? []) taken.add(scope + other);
    kept.push(token);
  }
  return kept.reverse().join(" ");
}

const cache = new Map<string, string>();
const CACHE_LIMIT = 1000;

export function cn(...parts: Array<string | false | null | undefined | 0>): string {
  const joined = parts.filter(Boolean).join(" ");
  const hit = cache.get(joined);
  if (hit !== undefined) return hit;
  const merged = merge(joined);
  if (cache.size >= CACHE_LIMIT) cache.delete(cache.keys().next().value as string);
  cache.set(joined, merged);
  return merged;
}

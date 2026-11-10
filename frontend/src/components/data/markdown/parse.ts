/**
 * Minimal, safe Markdown parser → plain AST. It never produces HTML strings: the renderer turns
 * the AST into React elements, so raw HTML in the source is always shown as text.
 *
 * Supported: ATX headings, paragraphs (soft and hard breaks), bullet / ordered / task lists with
 * nesting, fenced code (``` and ~~~), blockquotes, thematic breaks, inline code, **strong**,
 * *em* / _em_ (not inside snake_case words), ~~strikethrough~~, [links](https://…) and bare
 * http(s) URLs. Link targets other than absolute http(s) are dropped (text kept).
 */

export type Inline =
  | { type: "text"; value: string }
  | { type: "code"; value: string }
  | { type: "strong"; children: Inline[] }
  | { type: "em"; children: Inline[] }
  | { type: "del"; children: Inline[] }
  | { type: "link"; href: string | null; children: Inline[] }
  | { type: "break" };

export interface ListItem {
  /** null = not a task item; true/false = "- [x]" / "- [ ]". */
  checked: boolean | null;
  children: Block[];
}

export type Block =
  | { type: "heading"; level: number; children: Inline[] }
  | { type: "paragraph"; children: Inline[] }
  | { type: "code"; lang: string | null; value: string }
  | { type: "list"; ordered: boolean; start: number; items: ListItem[] }
  | { type: "blockquote"; children: Block[] }
  | { type: "hr" };

const MAX_DEPTH = 12;

const FENCE_RE = /^ {0,3}(`{3,}|~{3,})[ \t]*([^\s`]*)[^`]*$/;
const HEADING_RE = /^ {0,3}(#{1,6})(?:[ \t]+(.*?))?(?:[ \t]+#+)?[ \t]*$/;
const HR_RE = /^ {0,3}([-*_])(?:[ \t]*\1){2,}[ \t]*$/;
const QUOTE_RE = /^ {0,3}> ?(.*)$/;
const LIST_RE = /^( {0,3})([-*+]|\d{1,9}[.)])(?:([ \t]+)(.*))?$/;
const TASK_RE = /^\[([ xX])\](?:[ \t]+|$)(.*)$/;

/** Only absolute http(s) URLs survive; everything else (javascript:, data:, relative) → null. */
export function safeHref(raw: string): string | null {
  const candidate = raw.trim().replace(/^<(.*)>$/, "$1");
  if (!/^https?:\/\//i.test(candidate)) return null;
  try {
    const url = new URL(candidate);
    return url.protocol === "http:" || url.protocol === "https:" ? url.href : null;
  } catch {
    return null;
  }
}

function expandLeadingTabs(line: string): string {
  const m = /^[ \t]+/.exec(line);
  if (!m || !m[0].includes("\t")) return line;
  let width = 0;
  for (const ch of m[0]) width = ch === "\t" ? width + 4 - (width % 4) : width + 1;
  return " ".repeat(width) + line.slice(m[0].length);
}

const isBlank = (line: string) => line.trim() === "";
const indentOf = (line: string) => line.length - line.trimStart().length;

function isBlockStart(line: string): boolean {
  return FENCE_RE.test(line) || HEADING_RE.test(line) || HR_RE.test(line) || QUOTE_RE.test(line) || LIST_RE.test(line);
}

export function parseMarkdown(source: string): Block[] {
  const lines = source.replace(/\r\n?/g, "\n").split("\n").map(expandLeadingTabs);
  return parseBlocks(lines, 0);
}

function parseBlocks(lines: string[], depth: number): Block[] {
  if (depth > MAX_DEPTH) return [{ type: "paragraph", children: [{ type: "text", value: lines.join(" ").trim() }] }];
  const blocks: Block[] = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    if (isBlank(line)) {
      i += 1;
      continue;
    }

    const fence = FENCE_RE.exec(line);
    if (fence) {
      const marker = fence[1];
      const closeRe = new RegExp(`^ {0,3}${marker[0] === "`" ? "`" : "~"}{${marker.length},}[ \\t]*$`);
      const body: string[] = [];
      i += 1;
      while (i < lines.length && !closeRe.test(lines[i])) {
        body.push(lines[i]);
        i += 1;
      }
      i += 1; // closing fence (or end of input for an unclosed block)
      blocks.push({ type: "code", lang: fence[2] || null, value: body.join("\n") });
      continue;
    }

    const heading = HEADING_RE.exec(line);
    if (heading) {
      blocks.push({ type: "heading", level: heading[1].length, children: parseInline(heading[2] ?? "", depth) });
      i += 1;
      continue;
    }

    if (HR_RE.test(line)) {
      blocks.push({ type: "hr" });
      i += 1;
      continue;
    }

    if (QUOTE_RE.test(line)) {
      const inner: string[] = [];
      while (i < lines.length) {
        const q = QUOTE_RE.exec(lines[i]);
        if (q) inner.push(q[1]);
        else if (!isBlank(lines[i]) && !isBlockStart(lines[i]) && inner.length && !isBlank(inner[inner.length - 1])) inner.push(lines[i]);
        else break;
        i += 1;
      }
      blocks.push({ type: "blockquote", children: parseBlocks(inner, depth + 1) });
      continue;
    }

    if (LIST_RE.test(line)) {
      const [list, next] = parseList(lines, i, depth);
      blocks.push(list);
      i = next;
      continue;
    }

    const para: string[] = [];
    while (i < lines.length && !isBlank(lines[i]) && (para.length === 0 || !isBlockStart(lines[i]))) {
      para.push(lines[i]);
      i += 1;
    }
    blocks.push({ type: "paragraph", children: paragraphInlines(para, depth) });
  }
  return blocks;
}

function parseList(lines: string[], start: number, depth: number): [Block, number] {
  const first = LIST_RE.exec(lines[start])!;
  const ordered = /\d/.test(first[2]);
  const items: ListItem[] = [];
  let i = start;

  while (i < lines.length) {
    const m = LIST_RE.exec(lines[i]);
    if (!m || /\d/.test(m[2]) !== ordered) break;
    const gap = m[3] ? Math.min(m[3].length, 4) : 1;
    const contentIndent = m[1].length + m[2].length + gap;
    const itemLines = [m[4] ?? ""];
    i += 1;

    while (i < lines.length) {
      const l = lines[i];
      if (isBlank(l)) {
        let j = i + 1;
        while (j < lines.length && isBlank(lines[j])) j += 1;
        if (j < lines.length && indentOf(lines[j]) >= contentIndent) {
          for (; i < j; i += 1) itemLines.push("");
          continue;
        }
        break;
      }
      if (indentOf(l) >= contentIndent) itemLines.push(l.slice(contentIndent));
      else if (isBlockStart(l)) break;
      else if (!isBlank(itemLines[itemLines.length - 1])) itemLines.push(l.trim());
      else break;
      i += 1;
    }

    let checked: boolean | null = null;
    const task = TASK_RE.exec(itemLines[0]);
    if (task) {
      checked = task[1].toLowerCase() === "x";
      itemLines[0] = task[2];
    }
    items.push({ checked, children: parseBlocks(itemLines, depth + 1) });

    // Blank lines between sibling items keep the list going.
    let j = i;
    while (j < lines.length && isBlank(lines[j])) j += 1;
    const sibling = j < lines.length ? LIST_RE.exec(lines[j]) : null;
    if (sibling && /\d/.test(sibling[2]) === ordered && sibling[1].length < contentIndent) i = j;
    else break;
  }

  return [{ type: "list", ordered, start: ordered ? parseInt(first[2], 10) : 1, items }, i];
}

function paragraphInlines(lines: string[], depth: number): Inline[] {
  const out: Inline[] = [];
  lines.forEach((raw, idx) => {
    const isLast = idx === lines.length - 1;
    const hard = !isLast && (/ {2,}$/.test(raw) || /\\$/.test(raw));
    let text = raw.trim();
    if (hard && text.endsWith("\\")) text = text.slice(0, -1);
    out.push(...parseInline(text, depth));
    if (!isLast) out.push(hard ? { type: "break" } : { type: "text", value: " " });
  });
  return mergeText(out);
}

function mergeText(nodes: Inline[]): Inline[] {
  const merged: Inline[] = [];
  for (const node of nodes) {
    const prev = merged[merged.length - 1];
    if (node.type === "text" && prev?.type === "text") prev.value += node.value;
    else merged.push(node);
  }
  return merged;
}

const PUNCT = /[!-/:-@[-`{-~]/;
const ALNUM = /[\p{L}\p{N}]/u;
const BARE_URL = /^https?:\/\/[^\s<>]*[^\s<>.,;:!?'")\]*_~]/i;

function findClosingBracket(src: string, from: number): number {
  let level = 0;
  for (let k = from; k < src.length; k += 1) {
    const ch = src[k];
    if (ch === "\\") k += 1;
    else if (ch === "[") level += 1;
    else if (ch === "]") {
      if (level === 0) return k;
      level -= 1;
    }
  }
  return -1;
}

function findClosingParen(src: string, from: number): number {
  let level = 0;
  for (let k = from; k < src.length; k += 1) {
    const ch = src[k];
    if (ch === "\\") k += 1;
    else if (ch === "(") level += 1;
    else if (ch === ")") {
      if (level === 0) return k;
      level -= 1;
    }
  }
  return -1;
}

function findEmphasisClose(src: string, from: number, ch: string, len: number): number {
  const delim = ch.repeat(len);
  let pos = from;
  while (pos < src.length) {
    const j = src.indexOf(delim, pos);
    if (j < 0) return -1;
    const before = src[j - 1];
    const after = src[j + len];
    const okRun = len > 1 || (before !== ch && after !== ch);
    const okFlank = before !== undefined && !/\s/.test(before) && (ch !== "_" || after === undefined || !ALNUM.test(after));
    if (j > from && okRun && okFlank) return j;
    pos = j + 1;
  }
  return -1;
}

export function parseInline(src: string, depth = 0, inLink = false): Inline[] {
  if (depth > MAX_DEPTH) return src ? [{ type: "text", value: src }] : [];
  const out: Inline[] = [];
  let buf = "";
  const flush = () => {
    if (buf) out.push({ type: "text", value: buf });
    buf = "";
  };

  let i = 0;
  while (i < src.length) {
    const c = src[i];

    if (c === "\\" && i + 1 < src.length && PUNCT.test(src[i + 1])) {
      buf += src[i + 1];
      i += 2;
      continue;
    }

    if (c === "`") {
      let n = 1;
      while (src[i + n] === "`") n += 1;
      const run = "`".repeat(n);
      let j = src.indexOf(run, i + n);
      while (j >= 0 && src[j + n] === "`") j = src.indexOf(run, j + n + 1);
      if (j >= 0) {
        flush();
        let code = src.slice(i + n, j);
        if (code.length > 1 && code.startsWith(" ") && code.endsWith(" ") && code.trim()) code = code.slice(1, -1);
        out.push({ type: "code", value: code });
        i = j + n;
      } else {
        buf += run;
        i += n;
      }
      continue;
    }

    if (c === "[" && !inLink) {
      const close = findClosingBracket(src, i + 1);
      if (close > i && src[close + 1] === "(") {
        const parenEnd = findClosingParen(src, close + 2);
        if (parenEnd > close) {
          flush();
          const target = src.slice(close + 2, parenEnd).trim().split(/\s+/)[0] ?? "";
          out.push({ type: "link", href: safeHref(target), children: parseInline(src.slice(i + 1, close), depth + 1, true) });
          i = parenEnd + 1;
          continue;
        }
      }
      buf += c;
      i += 1;
      continue;
    }

    if ((c === "h" || c === "H") && !inLink && (i === 0 || /[\s(]/.test(src[i - 1]))) {
      const m = BARE_URL.exec(src.slice(i));
      if (m) {
        flush();
        out.push({ type: "link", href: safeHref(m[0]), children: [{ type: "text", value: m[0] }] });
        i += m[0].length;
        continue;
      }
    }

    if (c === "~" && src[i + 1] === "~" && src[i + 2] && !/\s/.test(src[i + 2])) {
      const j = findEmphasisClose(src, i + 2, "~", 2);
      if (j > 0) {
        flush();
        out.push({ type: "del", children: parseInline(src.slice(i + 2, j), depth + 1, inLink) });
        i = j + 2;
        continue;
      }
    }

    if (c === "*" || c === "_") {
      let n = 1;
      while (src[i + n] === c) n += 1;
      const prev = src[i - 1];
      const next = src[i + n];
      const canOpen = next !== undefined && !/\s/.test(next) && (c === "*" || prev === undefined || !ALNUM.test(prev));
      if (canOpen) {
        let matched = false;
        for (const len of n >= 3 ? [3, 2, 1] : n === 2 ? [2, 1] : [1]) {
          const j = findEmphasisClose(src, i + len, c, len);
          if (j <= 0) continue;
          flush();
          const children = parseInline(src.slice(i + len, j), depth + 1, inLink);
          if (len === 3) out.push({ type: "strong", children: [{ type: "em", children }] });
          else out.push(len === 2 ? { type: "strong", children } : { type: "em", children });
          i = j + len;
          matched = true;
          break;
        }
        if (matched) continue;
      }
      buf += src.slice(i, i + n);
      i += n;
      continue;
    }

    buf += c;
    i += 1;
  }
  flush();
  return out;
}

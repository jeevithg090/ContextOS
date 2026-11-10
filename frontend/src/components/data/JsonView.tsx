import { useState } from "react";
import { ChevronRight, ChevronsDownUp, ChevronsUpDown } from "lucide-react";
import { cn } from "@/lib/format";
import { CopyButton } from "./CopyButton";
import { RedactionMarker, isRedactedValue } from "./Redacted";

const CHILD_PAGE = 100;

export interface JsonViewProps {
  value: unknown;
  /** Levels expanded on first render (root = 0). */
  defaultExpandDepth?: number;
  /** Shows expand/collapse-all and copy controls. */
  toolbar?: boolean;
  /** Caption shown in the toolbar, e.g. "Input snapshot". */
  title?: string;
  className?: string;
  /** Tailwind max-height class for the scroll area, e.g. "max-h-96". */
  maxHeightClassName?: string;
}

/**
 * Read-only, collapsible JSON tree. Values flagged by the redaction engine render as markers
 * with an explanation, so redacted content is never mistaken for the original.
 */
export function JsonView({ value, defaultExpandDepth = 2, toolbar = true, title, className, maxHeightClassName = "max-h-[480px]" }: JsonViewProps) {
  // Remounting the tree with a new depth is the simplest correct "expand / collapse all".
  const [expand, setExpand] = useState({ depth: defaultExpandDepth, version: 0 });

  return (
    <div className={cn("overflow-hidden rounded-md border border-border bg-surface-2/60", className)}>
      {toolbar && (
        <div className="flex items-center justify-between gap-2 border-b border-border px-2.5 py-1">
          <span className="label-caps truncate">{title ?? "JSON"}</span>
          <div className="flex items-center">
            <button
              type="button"
              className="inline-flex h-6 w-6 items-center justify-center rounded text-fg-muted hover:bg-surface-3 hover:text-fg"
              onClick={() => setExpand((s) => ({ depth: Number.POSITIVE_INFINITY, version: s.version + 1 }))}
              aria-label="Expand all"
              title="Expand all"
            >
              <ChevronsUpDown className="h-3.5 w-3.5" aria-hidden />
            </button>
            <button
              type="button"
              className="inline-flex h-6 w-6 items-center justify-center rounded text-fg-muted hover:bg-surface-3 hover:text-fg"
              onClick={() => setExpand((s) => ({ depth: 1, version: s.version + 1 }))}
              aria-label="Collapse all"
              title="Collapse all"
            >
              <ChevronsDownUp className="h-3.5 w-3.5" aria-hidden />
            </button>
            <CopyButton size="xs" label="Copy JSON" value={() => safeStringify(value)} />
          </div>
        </div>
      )}
      <div className={cn("overflow-auto px-2.5 py-2 font-mono text-xs leading-5", maxHeightClassName)}>
        <ul aria-label={title ?? "JSON value"} key={expand.version}>
          <JsonNode name={null} value={value} depth={0} expandDepth={expand.depth} last />
        </ul>
      </div>
    </div>
  );
}

function safeStringify(value: unknown): string {
  try {
    return JSON.stringify(value, null, 2) ?? String(value);
  } catch {
    return String(value);
  }
}

interface NodeProps {
  name: string | number | null;
  value: unknown;
  depth: number;
  expandDepth: number;
  last: boolean;
}

function JsonNode({ name, value, depth, expandDepth, last }: NodeProps) {
  const isArray = Array.isArray(value);
  const isObject = value !== null && typeof value === "object" && !isArray;
  const [open, setOpen] = useState(depth < expandDepth);
  const [shown, setShown] = useState(CHILD_PAGE);

  const keyLabel =
    name === null ? null : (
      <span className="text-fg-muted">{typeof name === "number" ? name : JSON.stringify(name)}<span className="text-fg-faint">: </span></span>
    );
  const comma = last ? null : <span className="text-fg-faint">,</span>;

  if (!isArray && !isObject) {
    return (
      <li className="whitespace-pre-wrap break-all pl-4">
        {keyLabel}
        <Primitive value={value} />
        {comma}
      </li>
    );
  }

  const entries: Array<[string | number, unknown]> = isArray
    ? (value as unknown[]).map((v, i) => [i, v])
    : Object.entries(value as Record<string, unknown>);
  const [openBrace, closeBrace] = isArray ? ["[", "]"] : ["{", "}"];
  const summary = isArray ? `${entries.length} ${entries.length === 1 ? "item" : "items"}` : `${entries.length} ${entries.length === 1 ? "key" : "keys"}`;

  if (entries.length === 0) {
    return (
      <li className="pl-4">
        {keyLabel}
        <span className="text-fg-faint">{openBrace + closeBrace}</span>
        {comma}
      </li>
    );
  }

  return (
    <li>
      <button
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        className="group inline-flex max-w-full items-center rounded-sm text-left hover:bg-surface-3/60"
        aria-label={`${open ? "Collapse" : "Expand"} ${name === null ? "root" : String(name)} (${summary})`}
      >
        <ChevronRight className={cn("h-3.5 w-3.5 shrink-0 text-fg-faint transition-transform", open && "rotate-90")} aria-hidden />
        <span className="truncate">
          {keyLabel}
          <span className="text-fg-faint">{openBrace}</span>
          {!open && (
            <>
              <span className="mx-1 text-fg-faint">{summary}</span>
              <span className="text-fg-faint">{closeBrace}</span>
              {comma}
            </>
          )}
        </span>
      </button>
      {open && (
        <>
          <ul className="ml-[7px] border-l border-border pl-1.5">
            {entries.slice(0, shown).map(([k, v], i) => (
              <JsonNode key={String(k)} name={k} value={v} depth={depth + 1} expandDepth={expandDepth} last={i === entries.length - 1} />
            ))}
            {entries.length > shown && (
              <li className="pl-4">
                <button type="button" className="text-accent hover:underline" onClick={() => setShown((n) => n + CHILD_PAGE)}>
                  Show {Math.min(CHILD_PAGE, entries.length - shown)} more of {entries.length - shown} remaining
                </button>
              </li>
            )}
          </ul>
          <div className="pl-4">
            <span className="text-fg-faint">{closeBrace}</span>
            {comma}
          </div>
        </>
      )}
    </li>
  );
}

function Primitive({ value }: { value: unknown }) {
  if (isRedactedValue(value)) return <RedactionMarker text={value} />;
  if (typeof value === "string") return <span className="text-fg">{JSON.stringify(value)}</span>;
  if (typeof value === "number" || typeof value === "bigint") return <span className="num text-accent">{String(value)}</span>;
  if (typeof value === "boolean") return <span className="text-fg-muted">{String(value)}</span>;
  if (value === null) return <span className="italic text-fg-faint">null</span>;
  if (value === undefined) return <span className="italic text-fg-faint">undefined</span>;
  return <span className="text-fg-muted">{String(value)}</span>;
}

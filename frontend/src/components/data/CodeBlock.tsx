import { useLayoutEffect, useRef, useState, type ReactNode } from "react";
import { WrapText } from "lucide-react";
import { cn } from "@/lib/format";
import { CopyButton } from "./CopyButton";

export interface CodeBlockProps {
  code: string;
  /** Language label shown in the header ("python", "json", "bash"…). Display only. */
  language?: string | null;
  /** Optional caption shown before the language, e.g. a file path. */
  title?: ReactNode;
  /** Collapsed height in px before "Show all" appears. */
  maxHeight?: number;
  /** Initial soft-wrap state; the user can toggle it. */
  wrap?: boolean;
  showLineNumbers?: boolean;
  /** Extra header controls, rendered before wrap/copy. */
  actions?: ReactNode;
  className?: string;
}

/** Monospace code / payload viewer with copy, soft-wrap toggle and a height cap with expand. */
export function CodeBlock({ code, language, title, maxHeight = 320, wrap: initialWrap = false, showLineNumbers = false, actions, className }: CodeBlockProps) {
  const [wrap, setWrap] = useState(initialWrap);
  const [expanded, setExpanded] = useState(false);
  const [overflows, setOverflows] = useState(false);
  const preRef = useRef<HTMLPreElement>(null);
  const text = code.replace(/\n$/, "");
  const lines = showLineNumbers ? text.split("\n") : null;

  useLayoutEffect(() => {
    const el = preRef.current;
    if (!el) return;
    const measure = () => setOverflows(el.scrollHeight > maxHeight + 1);
    measure();
    if (typeof ResizeObserver === "undefined") return;
    const observer = new ResizeObserver(measure);
    observer.observe(el);
    return () => observer.disconnect();
  }, [text, wrap, maxHeight]);

  return (
    <div className={cn("overflow-hidden rounded-md border border-border bg-surface-2/60", className)}>
      <div className="flex h-8 items-center justify-between gap-2 border-b border-border pl-3 pr-1">
        <div className="flex min-w-0 items-center gap-2">
          {title && <span className="truncate font-mono text-2xs text-fg-muted">{title}</span>}
          {language && <span className="label-caps shrink-0">{language}</span>}
        </div>
        <div className="flex shrink-0 items-center">
          {actions}
          <button
            type="button"
            onClick={() => setWrap((w) => !w)}
            aria-pressed={wrap}
            aria-label="Wrap long lines"
            title={wrap ? "Disable line wrap" : "Wrap long lines"}
            className={cn("inline-flex h-6 w-6 items-center justify-center rounded transition-colors hover:bg-surface-3", wrap ? "text-accent" : "text-fg-muted hover:text-fg")}
          >
            <WrapText className="h-3.5 w-3.5" aria-hidden />
          </button>
          <CopyButton size="xs" value={text} label={language ? `Copy ${language} code` : "Copy code"} />
        </div>
      </div>
      <pre
        ref={preRef}
        tabIndex={0}
        aria-label={language ? `${language} code` : "Code"}
        style={expanded ? undefined : { maxHeight }}
        className={cn(
          "overflow-auto px-3 py-2.5 font-mono text-xs leading-5 text-fg focus-visible:outline-offset-[-2px]",
          wrap ? "whitespace-pre-wrap break-words" : "whitespace-pre",
        )}
      >
        {lines ? (
          <code className="grid grid-cols-[auto_1fr] gap-x-3">
            {lines.map((line, i) => (
              <span key={i} className="contents">
                <span className="num select-none text-right text-fg-faint" aria-hidden>
                  {i + 1}
                </span>
                <span>{line || " "}</span>
              </span>
            ))}
          </code>
        ) : (
          <code>{text}</code>
        )}
      </pre>
      {(overflows || expanded) && (
        <div className="border-t border-border px-3 py-1">
          <button type="button" className="text-2xs font-medium text-accent hover:underline" onClick={() => setExpanded((e) => !e)} aria-expanded={expanded}>
            {expanded ? "Collapse" : `Show all ${pluralLines(text)}`}
          </button>
        </div>
      )}
    </div>
  );
}

function pluralLines(text: string): string {
  const n = text.split("\n").length;
  return `${n} ${n === 1 ? "line" : "lines"}`;
}

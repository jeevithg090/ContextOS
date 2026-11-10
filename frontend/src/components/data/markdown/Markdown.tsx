import { createElement, useMemo, type ReactNode } from "react";
import { cn } from "@/lib/format";
import { CodeBlock } from "../CodeBlock";
import { RedactedText, REDACTION_PREFIX } from "../Redacted";
import { parseMarkdown, type Block, type Inline } from "./parse";

export interface MarkdownProps {
  source: string;
  /**
   * Added to heading levels so document headings sit under the page's own h1/h2
   * (default 1: "# Title" renders as <h2>).
   */
  headingOffset?: number;
  className?: string;
}

/**
 * Safe Markdown renderer for generated or user-written text (fix context, notes, policy
 * descriptions). Builds React elements from an AST — never dangerouslySetInnerHTML — so any
 * HTML in the source is displayed as text. Links open in a new tab and only http(s) is allowed.
 */
export function Markdown({ source, headingOffset = 1, className }: MarkdownProps) {
  const blocks = useMemo(() => parseMarkdown(source ?? ""), [source]);
  return <div className={cn("min-w-0 space-y-3 break-words text-[13px] leading-relaxed text-fg", className)}>{renderBlocks(blocks, headingOffset)}</div>;
}

const HEADING_STYLE: Record<number, string> = {
  1: "text-base font-semibold",
  2: "text-[14px] font-semibold",
  3: "text-[13px] font-semibold",
  4: "text-[13px] font-medium text-fg-muted",
  5: "label-caps",
  6: "label-caps",
};

function renderBlocks(blocks: Block[], offset: number): ReactNode[] {
  return blocks.map((block, i) => renderBlock(block, i, offset));
}

function renderBlock(block: Block, key: number, offset: number): ReactNode {
  switch (block.type) {
    case "heading": {
      const level = Math.min(6, Math.max(1, block.level + offset));
      return createElement(`h${level}`, { key, className: cn("pt-1 text-fg", HEADING_STYLE[block.level]) }, renderInlines(block.children));
    }
    case "paragraph":
      return <p key={key}>{renderInlines(block.children)}</p>;
    case "code":
      return <CodeBlock key={key} code={block.value} language={block.lang} maxHeight={360} />;
    case "hr":
      return <hr key={key} className="border-border" />;
    case "blockquote":
      return (
        <blockquote key={key} className="space-y-2 border-l-2 border-border-strong pl-3 text-fg-muted">
          {renderBlocks(block.children, offset)}
        </blockquote>
      );
    case "list": {
      const items = block.items.map((item, i) => {
        const tight = item.children.length === 1 && item.children[0].type === "paragraph";
        const content = tight ? renderInlines((item.children[0] as Extract<Block, { type: "paragraph" }>).children) : <div className="space-y-2">{renderBlocks(item.children, offset)}</div>;
        if (item.checked === null) return <li key={i} className="pl-1">{content}</li>;
        return (
          <li key={i} className="flex list-none items-start gap-2">
            <input
              type="checkbox"
              checked={item.checked}
              readOnly
              disabled
              aria-label={item.checked ? "Done" : "Not done"}
              className="mt-[5px] h-3.5 w-3.5 shrink-0 accent-[rgb(var(--accent))]"
            />
            <div className="min-w-0 flex-1">{content}</div>
          </li>
        );
      });
      const hasTasks = block.items.some((item) => item.checked !== null);
      return block.ordered ? (
        <ol key={key} start={block.start !== 1 ? block.start : undefined} className={cn("space-y-1 pl-5 marker:text-fg-faint", hasTasks ? "-ml-5 list-none" : "list-decimal")}>
          {items}
        </ol>
      ) : (
        <ul key={key} className={cn("space-y-1 pl-5 marker:text-fg-faint", hasTasks ? "-ml-5 list-none" : "list-disc")}>
          {items}
        </ul>
      );
    }
  }
}

function renderInlines(nodes: Inline[]): ReactNode[] {
  return nodes.map((node, i) => renderInline(node, i));
}

function renderInline(node: Inline, key: number): ReactNode {
  switch (node.type) {
    case "text":
      return node.value.includes(REDACTION_PREFIX) ? <RedactedText key={key} text={node.value} /> : node.value;
    case "code":
      return (
        <code key={key} className="rounded bg-surface-3 px-1 py-px font-mono text-[0.92em] text-fg">
          {node.value}
        </code>
      );
    case "strong":
      return (
        <strong key={key} className="font-semibold text-fg">
          {renderInlines(node.children)}
        </strong>
      );
    case "em":
      return <em key={key}>{renderInlines(node.children)}</em>;
    case "del":
      return (
        <del key={key} className="text-fg-muted">
          {renderInlines(node.children)}
        </del>
      );
    case "break":
      return <br key={key} />;
    case "link":
      return node.href ? (
        <a key={key} href={node.href} target="_blank" rel="noopener noreferrer nofollow" className="text-accent underline-offset-2 hover:underline">
          {renderInlines(node.children)}
        </a>
      ) : (
        <span key={key}>{renderInlines(node.children)}</span>
      );
  }
}

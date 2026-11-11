import { useId, useState, type KeyboardEvent } from "react";
import { Plus, Trash2 } from "lucide-react";
import { Button, IconButton, Input, Select } from "@/components/ui";
import { TOOL_CATEGORY_LABELS } from "../meta";
import { TOOL_CATEGORIES, type DeclaredToolInput, type ToolCategory } from "../types";

const CLAUDE_CODE_BUILTINS = ["Read", "Write", "Edit", "Glob", "Grep", "Bash", "WebFetch", "WebSearch", "Task"];
export const MAX_DECLARED_TOOLS = 200;

export interface DeclaredToolsEditorProps {
  value: DeclaredToolInput[];
  onChange: (next: DeclaredToolInput[]) => void;
  disabled?: boolean;
}

/**
 * Declared tools: what the agent is configured to use. ContextOS classifies each tool itself from its
 * name (e.g. mcp__github__create_issue); the category picked here is recorded only as a hint.
 */
export function DeclaredToolsEditor({ value, onChange, disabled }: DeclaredToolsEditorProps) {
  const [draft, setDraft] = useState("");
  const inputId = useId();
  const names = new Set(value.map((t) => t.name));

  const add = (raw: string) => {
    const incoming = raw
      .split(/[,\n]/)
      .map((n) => n.trim())
      .filter((n) => n && !names.has(n));
    if (incoming.length === 0) return;
    const unique = [...new Set(incoming)].slice(0, Math.max(0, MAX_DECLARED_TOOLS - value.length));
    onChange([...value, ...unique.map((name) => ({ name, category: null }))]);
    setDraft("");
  };
  const update = (index: number, patch: Partial<DeclaredToolInput>) => onChange(value.map((t, i) => (i === index ? { ...t, ...patch } : t)));
  const remove = (index: number) => onChange(value.filter((_, i) => i !== index));
  const onKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Enter") {
      e.preventDefault();
      add(draft);
    }
  };
  const missingBuiltins = CLAUDE_CODE_BUILTINS.filter((n) => !names.has(n));

  return (
    <div className="space-y-2">
      {value.length > 0 && (
        <ul className="divide-y divide-border/70 rounded border border-border" aria-label="Declared tools">
          {value.map((tool, i) => (
            <li key={tool.name} className="flex items-center gap-2 px-2 py-1.5">
              <span className="min-w-0 flex-1 truncate font-mono text-xs text-fg" title={tool.name}>
                {tool.name}
              </span>
              <label className="sr-only" htmlFor={`${inputId}-cat-${i}`}>
                Category hint for {tool.name}
              </label>
              <Select
                id={`${inputId}-cat-${i}`}
                value={tool.category ?? ""}
                disabled={disabled}
                onChange={(e) => update(i, { category: (e.target.value || null) as ToolCategory | null })}
                className="!h-7 !w-40 !text-xs"
              >
                <option value="">Detect from name</option>
                {TOOL_CATEGORIES.map((c) => (
                  <option key={c} value={c}>
                    Hint: {TOOL_CATEGORY_LABELS[c]}
                  </option>
                ))}
              </Select>
              {!disabled && (
                <IconButton label={`Remove ${tool.name}`} onClick={() => remove(i)}>
                  <Trash2 className="h-3.5 w-3.5" aria-hidden />
                </IconButton>
              )}
            </li>
          ))}
        </ul>
      )}
      {!disabled && (
        <div className="flex flex-wrap items-center gap-2">
          <label htmlFor={inputId} className="sr-only">
            Add tool names
          </label>
          <Input
            id={inputId}
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={onKeyDown}
            placeholder="Tool name, e.g. Bash or mcp__github__create_issue"
            className="!h-7 min-w-[220px] flex-1 font-mono !text-xs"
            maxLength={200}
          />
          <Button size="sm" variant="outline" icon={<Plus className="h-3.5 w-3.5" aria-hidden />} onClick={() => add(draft)} disabled={!draft.trim()}>
            Add
          </Button>
          {missingBuiltins.length > 0 && (
            <Button size="sm" variant="ghost" onClick={() => add(missingBuiltins.join(","))} title={missingBuiltins.join(", ")}>
              Add Claude Code built-ins
            </Button>
          )}
        </div>
      )}
      <p className="text-2xs text-fg-faint">
        ContextOS classifies each tool from its name; a hint is only used when the name carries no signal, and both are recorded. Comma-separate to add
        several.
      </p>
    </div>
  );
}

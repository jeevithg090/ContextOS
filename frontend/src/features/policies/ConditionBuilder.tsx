/** Visual editor for nested ALL / ANY / NOT condition groups. The JSON tab edits the same value. */
import { useEffect, useRef, useState } from "react";
import { FolderPlus, Plus, Trash2 } from "lucide-react";
import { Button, IconButton } from "@/components/ui";
import { SegmentedControl } from "@/components/data";
import { ConditionRow, NotToggle } from "./ConditionRow";
import {
  MAX_DEPTH,
  emptyGroup,
  emptyLeaf,
  parseConditions,
  serializeConditions,
  updateNode,
  type ParseResult,
  type UiGroup,
  type UiNode,
} from "./conditions";
import type { FieldSpec, OperatorSpec } from "./types";

interface Props {
  conditions: unknown;
  onChange: (conditions: unknown) => void;
  catalog: FieldSpec[];
  operators: OperatorSpec[];
  readOnly?: boolean;
  /** Called when the stored JSON cannot be shown visually (the user should switch to JSON). */
  onUnsupported?: () => void;
}

/** Drop nested groups left empty by a removal; the root always keeps at least one row. */
function normalize(root: UiGroup): UiGroup {
  const prune = (node: UiNode): UiNode | null => {
    if (node.kind !== "group") return node;
    const children = node.children.map(prune).filter((c): c is UiNode => c !== null);
    return children.length ? { ...node, children } : null;
  };
  const children = root.children.map(prune).filter((c): c is UiNode => c !== null);
  return { ...root, children: children.length ? children : [emptyLeaf()] };
}

export function ConditionBuilder({ conditions, onChange, catalog, operators, readOnly, onUnsupported }: Props) {
  const [state, setState] = useState<ParseResult>(() => parseConditions(conditions));
  const emitted = useRef(JSON.stringify(conditions ?? {}));

  // Re-parse only when the value changed outside the builder (JSON tab, reset, policy switch).
  useEffect(() => {
    const text = JSON.stringify(conditions ?? {});
    if (text !== emitted.current) {
      emitted.current = text;
      setState(parseConditions(conditions));
    }
  }, [conditions]);

  if (!state.ok) {
    return (
      <div role="note" className="rounded-md border border-warn/30 bg-warn/10 px-3 py-2.5 text-xs text-fg-muted">
        <p className="font-medium text-warn">These conditions can’t be shown in the visual builder</p>
        <p className="mt-1">The JSON contains {state.reason}. Edit it in the JSON tab, where validation explains what to fix.</p>
        {onUnsupported && (
          <Button size="xs" variant="outline" className="mt-2" onClick={onUnsupported}>
            Open JSON
          </Button>
        )}
      </div>
    );
  }

  const commit = (tree: UiGroup) => {
    const next = normalize(tree);
    setState({ ok: true, tree: next });
    const json = serializeConditions(next);
    emitted.current = JSON.stringify(json);
    onChange(json);
  };

  return (
    <GroupEditor
      group={state.tree}
      depth={0}
      catalog={catalog}
      operators={operators}
      readOnly={readOnly}
      onEdit={(key, fn) => commit(updateNode(state.tree, key, fn))}
    />
  );
}

function GroupEditor({
  group,
  depth,
  catalog,
  operators,
  readOnly,
  onEdit,
}: {
  group: UiGroup;
  depth: number;
  catalog: FieldSpec[];
  operators: OperatorSpec[];
  readOnly?: boolean;
  onEdit: (key: string, fn: (node: UiNode) => UiNode | null) => void;
}) {
  const isRoot = depth === 0;
  const joiner = group.combinator === "all" ? "AND" : "OR";
  const editGroup = (fn: (g: UiGroup) => UiGroup) => onEdit(group.key, (n) => (n.kind === "group" ? fn(n) : n));

  return (
    <div className={isRoot ? "space-y-2" : "space-y-2 rounded-md border border-border bg-surface-2/40 p-2.5"}>
      <div className="flex flex-wrap items-center gap-2">
        {!isRoot && <NotToggle negated={group.negated} disabled={readOnly} label="Negate this group" onToggle={() => editGroup((g) => ({ ...g, negated: !g.negated }))} />}
        <span className="text-xs text-fg-muted">{group.negated ? "Match unless" : "Match when"}</span>
        <SegmentedControl
          aria-label="Combine conditions with"
          value={group.combinator}
          onChange={(combinator) => !readOnly && editGroup((g) => ({ ...g, combinator }))}
          options={[
            { value: "all", label: "all", disabled: readOnly && group.combinator !== "all" },
            { value: "any", label: "any", disabled: readOnly && group.combinator !== "any" },
          ]}
        />
        <span className="text-xs text-fg-muted">of these are true</span>
        {!isRoot && !readOnly && (
          <IconButton label="Remove group" className="ml-auto text-fg-faint hover:text-danger" onClick={() => onEdit(group.key, () => null)}>
            <Trash2 className="h-3.5 w-3.5" aria-hidden />
          </IconButton>
        )}
      </div>

      <ol className="space-y-1.5 border-l border-border-strong/70 pl-3">
        {group.children.map((child, i) => (
          <li key={child.key} className="relative">
            {i > 0 && <div className="mb-1 font-mono text-2xs font-semibold text-fg-faint">{joiner}</div>}
            {child.kind === "group" ? (
              <GroupEditor group={child} depth={depth + 1} catalog={catalog} operators={operators} readOnly={readOnly} onEdit={onEdit} />
            ) : (
              <ConditionRow
                leaf={child}
                catalog={catalog}
                operators={operators}
                readOnly={readOnly}
                onChange={(leaf) => onEdit(child.key, () => leaf)}
                onRemove={() => onEdit(child.key, () => null)}
              />
            )}
          </li>
        ))}
      </ol>

      {!readOnly && (
        <div className="flex gap-1.5 pl-3">
          <Button size="xs" variant="ghost" icon={<Plus className="h-3 w-3" aria-hidden />} onClick={() => editGroup((g) => ({ ...g, children: [...g.children, emptyLeaf()] }))}>
            Condition
          </Button>
          <Button
            size="xs"
            variant="ghost"
            disabled={depth + 1 >= MAX_DEPTH - 1}
            title={depth + 1 >= MAX_DEPTH - 1 ? `Groups can nest at most ${MAX_DEPTH} levels` : undefined}
            icon={<FolderPlus className="h-3 w-3" aria-hidden />}
            onClick={() => editGroup((g) => ({ ...g, children: [...g.children, emptyGroup(g.combinator === "all" ? "any" : "all")] }))}
          >
            Group
          </Button>
        </div>
      )}
    </div>
  );
}

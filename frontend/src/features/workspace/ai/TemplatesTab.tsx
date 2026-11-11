import { useState } from "react";
import { Link } from "react-router-dom";
import { Copy, LayoutTemplate, Pencil, Plus, Trash2 } from "lucide-react";
import { ConfirmDialog, DataTable, Section, type DataTableColumn } from "@/components/data";
import { Badge, Button, IconButton, useToast } from "@/components/ui";
import { timeAgo } from "@/lib/format";
import { useDeleteTemplate } from "./api";
import { mutationMessage, useCanWrite, useCatalogueMaps, useTemplateGroups } from "./hooks";
import { mayModify, optionsSummary } from "./meta";
import { ModeAccess } from "./ModeCards";
import { TemplateEditorDialog, templateDraftFrom, type TemplateDraft } from "./TemplateEditorDialog";
import type { PromptTemplate } from "./types";

type Editor = { mode: "create"; initial: TemplateDraft | null; title: string } | { mode: "edit"; template: PromptTemplate };

const templateUseHref = (t: PromptTemplate) => `/work/fix-context?template=${encodeURIComponent(t.id)}`;

/** Built-in templates (read-only, one per mode) and organisation templates (create, edit, delete). */
export function TemplatesTab() {
  const toast = useToast();
  const canWrite = useCanWrite();
  const { templates, builtin, org } = useTemplateGroups();
  const { modes } = useCatalogueMaps();
  const remove = useDeleteTemplate();
  const [editor, setEditor] = useState<Editor | null>(null);
  const [deleting, setDeleting] = useState<PromptTemplate | null>(null);

  const customise = (t: PromptTemplate) =>
    setEditor({ mode: "create", initial: templateDraftFrom(t, { name: `${t.name} (custom)` }), title: t.is_builtin ? `Customise “${t.name}”` : `Duplicate “${t.name}”` });

  const columns = (editable: boolean): Array<DataTableColumn<PromptTemplate>> => [
    {
      key: "name",
      header: "Template",
      render: (t) => (
        <div className="min-w-0 max-w-[380px]">
          <div className="truncate text-[13px] font-medium text-fg">{t.name}</div>
          {t.description && <div className="line-clamp-2 text-2xs text-fg-muted">{t.description}</div>}
        </div>
      ),
    },
    {
      key: "mode",
      header: "Mode",
      render: (t) => (
        <div className="flex flex-col gap-0.5 whitespace-nowrap">
          <span className="text-xs text-fg">{t.mode_label}</span>
          <ModeAccess mayModify={mayModify(modes.get(t.mode), t.options)} />
        </div>
      ),
    },
    { key: "preset", header: "Agent", hideBelow: "md", render: (t) => <span className="whitespace-nowrap text-xs text-fg-muted">{t.preset_label}</span> },
    { key: "options", header: "Options", hideBelow: "lg", render: (t) => <span className="text-2xs text-fg-muted">{optionsSummary(t.options)}</span> },
    {
      key: "overrides",
      header: "Section instructions",
      hideBelow: "lg",
      render: (t) => {
        const n = Object.keys(t.section_overrides).length;
        return n ? <Badge tone="accent" title={Object.keys(t.section_overrides).join(", ")}>{n} section{n === 1 ? "" : "s"}</Badge> : <span className="text-2xs text-fg-faint">None</span>;
      },
    },
    ...(editable ? [{ key: "updated", header: "Updated", hideBelow: "sm" as const, render: (t: PromptTemplate) => <span className="whitespace-nowrap text-xs text-fg-muted">{timeAgo(t.updated_at ?? t.created_at)}</span> }] : []),
    {
      key: "actions",
      header: <span className="sr-only">Actions</span>,
      align: "right",
      render: (t) => (
        <div className="flex items-center justify-end gap-1">
          <Link to={templateUseHref(t)} className="inline-flex h-7 items-center rounded px-2 text-xs font-medium text-accent hover:bg-surface-2" title="Pick a task and generate with this template">
            Use
          </Link>
          {canWrite && (
            <IconButton label={t.is_builtin ? `Customise ${t.name}` : `Duplicate ${t.name}`} onClick={() => customise(t)}>
              <Copy className="h-3.5 w-3.5" aria-hidden />
            </IconButton>
          )}
          {canWrite && editable && (
            <>
              <IconButton label={`Edit ${t.name}`} onClick={() => setEditor({ mode: "edit", template: t })}>
                <Pencil className="h-3.5 w-3.5" aria-hidden />
              </IconButton>
              <IconButton label={`Delete ${t.name}`} className="hover:text-danger" onClick={() => setDeleting(t)}>
                <Trash2 className="h-3.5 w-3.5" aria-hidden />
              </IconButton>
            </>
          )}
        </div>
      ),
    },
  ];

  return (
    <div className="space-y-4">
      <Section
        title="Organisation templates"
        description="Shared with everyone in your organisation. Use one in AI Fix Context to start from its mode, agent, options and extra section instructions."
        flush
        actions={
          canWrite ? (
            <Button size="sm" variant="primary" icon={<Plus className="h-3.5 w-3.5" aria-hidden />} onClick={() => setEditor({ mode: "create", initial: null, title: "New template" })}>
              New template
            </Button>
          ) : undefined
        }
      >
        <DataTable
          aria-label="Organisation templates"
          columns={columns(true)}
          rows={org}
          rowKey={(t) => t.id}
          loading={templates.isLoading}
          error={templates.error}
          onRetry={() => void templates.refetch()}
          dense
          empty={{
            icon: <LayoutTemplate className="h-4 w-4" />,
            title: "No organisation templates yet",
            description: canWrite ? "Create one from scratch, customise a built-in template below, or use “Save as template” in AI Fix Context." : "Someone with write access can create templates for your organisation.",
          }}
        />
      </Section>

      <Section title="Built-in templates" description="One per prompt mode, with option defaults tuned for that mode. Read-only — customise one to change it." flush>
        <DataTable aria-label="Built-in templates" columns={columns(false)} rows={builtin} rowKey={(t) => t.id} loading={templates.isLoading} error={templates.error} onRetry={() => void templates.refetch()} dense empty={{ title: "No built-in templates" }} />
      </Section>

      <TemplateEditorDialog
        open={!!editor}
        onOpenChange={(o) => !o && setEditor(null)}
        initial={editor ? (editor.mode === "edit" ? templateDraftFrom(editor.template) : editor.initial) : null}
        templateId={editor?.mode === "edit" ? editor.template.id : undefined}
        title={editor ? (editor.mode === "edit" ? `Edit “${editor.template.name}”` : editor.title) : ""}
      />

      <ConfirmDialog
        open={!!deleting}
        onOpenChange={(o) => !o && setDeleting(null)}
        title={`Delete “${deleting?.name ?? ""}”?`}
        description="The template is removed for everyone in your organisation."
        confirmLabel="Delete template"
        destructive
        onConfirm={() =>
          new Promise<void>((resolve, reject) => {
            if (!deleting) return resolve();
            remove.mutate(deleting.id, {
              onSuccess: () => {
                toast.success("Template deleted", deleting.name);
                resolve();
              },
              onError: (err) => reject(new Error(mutationMessage(err))),
            });
          })
        }
      >
        <p className="text-xs text-fg-muted">Prompts already generated with it keep their content. If one of their sections is regenerated later, this template’s extra section instructions are no longer applied.</p>
      </ConfirmDialog>
    </div>
  );
}

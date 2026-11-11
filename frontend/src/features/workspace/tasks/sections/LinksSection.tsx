/** Code links: branches, commits, pull requests and deployments that carry the fix. */
import { useId, useState, type FormEvent } from "react";
import { ExternalLink, GitBranch, GitCommitHorizontal, GitPullRequest, Plus, Rocket, Trash2 } from "lucide-react";
import { Section, safeHref } from "@/components/data";
import { Badge, Button, Field, IconButton, Input, Select, useToast } from "@/components/ui";
import type { Tone } from "@/lib/domain";
import { timeAgo } from "@/lib/format";
import { useAddLink, useRemoveLink } from "../../api";
import { LINK_KINDS, type LinkKind, type PullRequestState, type TaskDetail, type TaskLink } from "../../types";
import { describeError } from "../hooks";

const KIND_META: Record<LinkKind, { label: string; icon: typeof GitBranch; refLabel: string; refPlaceholder: string; urlHint: string; refHint?: string }> = {
  branch: { label: "Branch", icon: GitBranch, refLabel: "Branch name", refPlaceholder: "fix/ctx-12-injection-guard", urlHint: "Optional, http(s) only.", refHint: "Required." },
  commit: { label: "Commit", icon: GitCommitHorizontal, refLabel: "Commit SHA", refPlaceholder: "3f2a9c1", urlHint: "Optional, http(s) only.", refHint: "Required: 7–64 hex characters." },
  pull_request: { label: "Pull request", icon: GitPullRequest, refLabel: "Reference", refPlaceholder: "#482", urlHint: "Required, http(s) only." },
  deployment: { label: "Deployment", icon: Rocket, refLabel: "Environment", refPlaceholder: "staging", urlHint: "A URL or an environment is required." },
};

const PR_TONES: Record<PullRequestState, Tone> = { open: "accent", draft: "neutral", merged: "ok", closed: "neutral" };

function LinkRow({ link, canWrite, onRemove }: { link: TaskLink; canWrite: boolean; onRemove: () => void }) {
  const meta = KIND_META[link.kind];
  const Icon = meta.icon;
  const href = link.url ? safeHref(link.url) : null;
  const text = link.title || link.ref || link.url || meta.label;
  return (
    <li className="group flex items-center gap-2 rounded px-1 py-1 hover:bg-surface-2">
      <Icon className="h-3.5 w-3.5 shrink-0 text-fg-faint" aria-label={meta.label} />
      {href ? (
        <a href={href} target="_blank" rel="noreferrer noopener" className="inline-flex min-w-0 items-center gap-1 truncate text-[13px] text-accent hover:underline">
          <span className="truncate">{text}</span>
          <ExternalLink className="h-3 w-3 shrink-0" aria-hidden />
        </a>
      ) : (
        <span className="min-w-0 truncate text-[13px] text-fg">{text}</span>
      )}
      {link.ref && link.title && <span className="shrink-0 font-mono text-2xs text-fg-faint">{link.ref}</span>}
      {link.state && <Badge tone={PR_TONES[link.state]}>{link.state}</Badge>}
      <span className="ml-auto shrink-0 text-2xs text-fg-faint">{link.added_at ? timeAgo(link.added_at) : ""}</span>
      {canWrite && (
        <IconButton label={`Remove ${meta.label.toLowerCase()} ${text}`} className="h-6 w-6 opacity-0 group-hover:opacity-100 focus:opacity-100" onClick={onRemove}>
          <Trash2 className="h-3 w-3" aria-hidden />
        </IconButton>
      )}
    </li>
  );
}

function AddLinkForm({ taskId, onDone }: { taskId: string; onDone: () => void }) {
  const ids = { kind: useId(), url: useId(), title: useId(), ref: useId(), state: useId() };
  const toast = useToast();
  const add = useAddLink();
  const [kind, setKind] = useState<LinkKind>("pull_request");
  const [url, setUrl] = useState("");
  const [title, setTitle] = useState("");
  const [ref, setRef] = useState("");
  const [state, setState] = useState<PullRequestState>("open");
  const meta = KIND_META[kind];

  const submit = (e: FormEvent) => {
    e.preventDefault();
    add.mutate(
      { taskId, kind, url: url.trim() || null, title: title.trim() || null, ref: ref.trim() || null, state: kind === "pull_request" ? state : null },
      {
        onSuccess: () => {
          toast.success(`${meta.label} linked`, kind === "pull_request" ? "If this column has a “pull request linked” rule, the task moves automatically." : undefined);
          onDone();
        },
      },
    );
  };

  return (
    <form onSubmit={submit} className="space-y-3 rounded-md border border-border bg-surface-2/40 p-3">
      <div className="grid gap-3 sm:grid-cols-[150px_1fr]">
        <Field label="Kind" htmlFor={ids.kind}>
          <Select id={ids.kind} value={kind} onChange={(e) => setKind(e.target.value as LinkKind)}>
            {LINK_KINDS.map((k) => (
              <option key={k} value={k}>
                {KIND_META[k].label}
              </option>
            ))}
          </Select>
        </Field>
        <Field label="URL" htmlFor={ids.url} hint={meta.urlHint}>
          <Input id={ids.url} type="url" value={url} maxLength={2000} onChange={(e) => setUrl(e.target.value)} placeholder="https://github.com/acme/app/pull/482" />
        </Field>
      </div>
      <div className={`grid gap-3 ${kind === "pull_request" ? "sm:grid-cols-[1fr_160px_120px]" : "sm:grid-cols-2"}`}>
        <Field label="Title (optional)" htmlFor={ids.title}>
          <Input id={ids.title} value={title} maxLength={300} onChange={(e) => setTitle(e.target.value)} />
        </Field>
        <Field label={meta.refLabel} htmlFor={ids.ref} hint={meta.refHint}>
          <Input id={ids.ref} value={ref} maxLength={200} onChange={(e) => setRef(e.target.value)} placeholder={meta.refPlaceholder} className="font-mono !text-xs" />
        </Field>
        {kind === "pull_request" && (
          <Field label="State" htmlFor={ids.state}>
            <Select id={ids.state} value={state} onChange={(e) => setState(e.target.value as PullRequestState)}>
              {(["open", "draft", "merged", "closed"] as const).map((s) => (
                <option key={s} value={s}>
                  {s[0].toUpperCase() + s.slice(1)}
                </option>
              ))}
            </Select>
          </Field>
        )}
      </div>
      {add.error && (
        <p role="alert" className="text-xs text-danger">
          {describeError(add.error)}
        </p>
      )}
      <div className="flex justify-end gap-2">
        <Button size="sm" variant="ghost" onClick={onDone} disabled={add.isPending}>
          Cancel
        </Button>
        <Button size="sm" variant="primary" type="submit" loading={add.isPending} disabled={!url.trim() && !ref.trim()}>
          Add link
        </Button>
      </div>
    </form>
  );
}

export function LinksSection({ task, canWrite }: { task: TaskDetail; canWrite: boolean }) {
  const toast = useToast();
  const remove = useRemoveLink();
  const [adding, setAdding] = useState(false);
  const all = LINK_KINDS.flatMap((k) => task.links[k] ?? []);

  return (
    <Section
      title="Code links"
      description="Branches, commits, pull requests and deployments for this work. A merged PR is evidence of a change, not of a working fix."
      actions={
        canWrite && !adding ? (
          <Button size="xs" variant="outline" icon={<Plus className="h-3 w-3" aria-hidden />} onClick={() => setAdding(true)}>
            Add link
          </Button>
        ) : undefined
      }
      bodyClassName="space-y-3"
    >
      {all.length === 0 && !adding && <p className="text-xs text-fg-faint">No branches, commits, pull requests or deployments linked.</p>}
      {LINK_KINDS.map((k) =>
        (task.links[k] ?? []).length > 0 ? (
          <div key={k}>
            <div className="label-caps mb-1">{KIND_META[k].label}s</div>
            <ul>
              {(task.links[k] ?? []).map((link) => (
                <LinkRow
                  key={`${k}-${link.index}`}
                  link={link}
                  canWrite={canWrite}
                  onRemove={() =>
                    remove.mutate(
                      { taskId: task.id, kind: k, index: link.index },
                      { onSuccess: () => toast.success("Link removed"), onError: (e) => toast.error("Link not removed", describeError(e)) },
                    )
                  }
                />
              ))}
            </ul>
          </div>
        ) : null,
      )}
      {adding && <AddLinkForm taskId={task.id} onDone={() => setAdding(false)} />}
    </Section>
  );
}

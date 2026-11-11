/** Discussion on a task: Markdown comments; authors edit their own, authors or admins delete. */
import { useState } from "react";
import { MessageSquare, Pencil, Trash2 } from "lucide-react";
import { ConfirmDialog, Markdown, SegmentedControl, Section } from "@/components/data";
import { Button, EmptyState, IconButton, Textarea, useToast } from "@/components/ui";
import { useAuth } from "@/features/auth/AuthProvider";
import { formatDateTime, timeAgo } from "@/lib/format";
import { initials } from "../../analytics/taskMeta";
import { useAddComment, useDeleteComment, useEditComment } from "../../api";
import type { TaskComment, TaskDetail } from "../../types";
import { describeError } from "../hooks";

function Composer({ initial = "", submitLabel, pending, onSubmit, onCancel, autoFocus }: { initial?: string; submitLabel: string; pending: boolean; onSubmit: (body: string) => Promise<unknown>; onCancel?: () => void; autoFocus?: boolean }) {
  const [body, setBody] = useState(initial);
  const [mode, setMode] = useState<"write" | "preview">("write");
  const submit = () => {
    const text = body.trim();
    if (!text || pending) return;
    void onSubmit(text).then(
      () => {
        setBody("");
        setMode("write");
      },
      () => undefined,
    );
  };
  return (
    <div className="space-y-2">
      <SegmentedControl<"write" | "preview">
        aria-label="Comment editor mode"
        value={mode}
        onChange={setMode}
        options={[
          { value: "write", label: "Write" },
          { value: "preview", label: "Preview" },
        ]}
      />
      {mode === "write" ? (
        <Textarea
          autoFocus={autoFocus}
          rows={3}
          value={body}
          maxLength={50_000}
          aria-label="Comment"
          placeholder="Add a comment — Markdown supported, ⌘/Ctrl + Enter to send"
          onChange={(e) => setBody(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter" && (e.metaKey || e.ctrlKey)) {
              e.preventDefault();
              submit();
            } else if (e.key === "Escape" && onCancel) {
              e.stopPropagation();
              onCancel();
            }
          }}
        />
      ) : (
        <div className="min-h-[72px] rounded border border-border bg-surface-2 px-3 py-2">{body.trim() ? <Markdown source={body} headingOffset={3} /> : <p className="text-xs text-fg-faint">Nothing to preview.</p>}</div>
      )}
      <div className="flex items-center justify-between gap-2">
        <span className="text-2xs text-fg-faint">Secrets in comments are redacted before storage.</span>
        <span className="flex gap-1.5">
          {onCancel && (
            <Button size="xs" variant="ghost" onClick={onCancel} disabled={pending}>
              Cancel
            </Button>
          )}
          <Button size="xs" variant="primary" onClick={submit} loading={pending} disabled={!body.trim() || body.trim() === initial.trim()}>
            {submitLabel}
          </Button>
        </span>
      </div>
    </div>
  );
}

function CommentItem({ comment, taskId, canEdit, canDelete, onDelete }: { comment: TaskComment; taskId: string; canEdit: boolean; canDelete: boolean; onDelete: () => void }) {
  const toast = useToast();
  const edit = useEditComment();
  const [editing, setEditing] = useState(false);
  const author = comment.author?.name ?? "Former member";
  return (
    <li className="group flex gap-3 py-3">
      <span className="inline-flex h-7 w-7 shrink-0 items-center justify-center rounded-full bg-surface-3 text-2xs font-semibold text-fg-muted" aria-hidden>
        {initials(author)}
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="text-[13px] font-medium text-fg">{author}</span>
          <time dateTime={comment.created_at} title={formatDateTime(comment.created_at)} className="text-2xs text-fg-faint">
            {timeAgo(comment.created_at)}
          </time>
          {comment.edited_at && (
            <span className="text-2xs text-fg-faint" title={`Edited ${formatDateTime(comment.edited_at)}`}>
              (edited)
            </span>
          )}
          <span className="ml-auto flex gap-0.5 opacity-0 transition-opacity focus-within:opacity-100 group-hover:opacity-100">
            {canEdit && !editing && (
              <IconButton label="Edit comment" className="h-6 w-6" onClick={() => setEditing(true)}>
                <Pencil className="h-3 w-3" aria-hidden />
              </IconButton>
            )}
            {canDelete && (
              <IconButton label="Delete comment" className="h-6 w-6" onClick={onDelete}>
                <Trash2 className="h-3 w-3" aria-hidden />
              </IconButton>
            )}
          </span>
        </div>
        <div className="mt-1">
          {editing ? (
            <Composer
              autoFocus
              initial={comment.body}
              submitLabel="Save"
              pending={edit.isPending}
              onCancel={() => setEditing(false)}
              onSubmit={(body) =>
                edit.mutateAsync({ taskId, commentId: comment.id, body }).then(
                  () => setEditing(false),
                  (e: unknown) => {
                    toast.error("Comment not saved", describeError(e));
                    throw e;
                  },
                )
              }
            />
          ) : (
            <Markdown source={comment.body} headingOffset={3} />
          )}
        </div>
      </div>
    </li>
  );
}

export function CommentsSection({ task, canWrite }: { task: TaskDetail; canWrite: boolean }) {
  const { me, can } = useAuth();
  const toast = useToast();
  const add = useAddComment();
  const remove = useDeleteComment();
  const [deleting, setDeleting] = useState<TaskComment | null>(null);
  const comments = [...task.comments].sort((a, b) => a.created_at.localeCompare(b.created_at));
  const isAdmin = can("admin");

  return (
    <Section title="Comments" description={comments.length > 0 ? `${comments.length} comment${comments.length === 1 ? "" : "s"}` : undefined}>
      {comments.length === 0 ? (
        <EmptyState className="py-6" icon={<MessageSquare className="h-4 w-4" aria-hidden />} title="No comments yet" description="Discuss the approach, record decisions and hand-offs here." />
      ) : (
        <ol className="-mt-2 divide-y divide-border/70">
          {comments.map((c) => {
            const own = !!me && c.author?.id === me.user.id;
            return <CommentItem key={c.id} comment={c} taskId={task.id} canEdit={own && canWrite} canDelete={canWrite && (own || isAdmin)} onDelete={() => setDeleting(c)} />;
          })}
        </ol>
      )}
      {canWrite && (
        <div className="mt-3 border-t border-border pt-3">
          <Composer
            submitLabel="Comment"
            pending={add.isPending}
            onSubmit={(body) =>
              add.mutateAsync({ taskId: task.id, body }).catch((e: unknown) => {
                toast.error("Comment not posted", describeError(e));
                throw e;
              })
            }
          />
        </div>
      )}
      <ConfirmDialog
        open={deleting !== null}
        onOpenChange={(open) => !open && setDeleting(null)}
        destructive
        title="Delete this comment?"
        description={deleting && deleting.author?.id !== me?.user.id ? `You are deleting ${deleting.author?.name ?? "another member"}'s comment as an administrator.` : "The comment is removed from the task. This cannot be undone."}
        confirmLabel="Delete comment"
        onConfirm={async () => {
          if (!deleting) return;
          await remove.mutateAsync({ taskId: task.id, commentId: deleting.id });
          toast.success("Comment deleted");
        }}
      />
    </Section>
  );
}

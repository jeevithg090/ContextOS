/** Activity history: who changed what, newest first. Entries without an actor were made by automation. */
import { useMemo, useState } from "react";
import { Bot } from "lucide-react";
import { Section, SegmentedControl, Timeline, type TimelineItem } from "@/components/data";
import type { TaskDetail } from "../../types";
import { describeActivity } from "../activityText";

type Filter = "all" | "changes" | "evidence";
const EVIDENCE_KINDS = new Set(["verification", "verification_regressed", "fix_attempt_created", "fix_attempt_updated", "linked", "unlinked", "reference_added", "reference_removed", "attachment_added", "attachment_removed"]);
const NOISE_KINDS = new Set(["commented", "comment_edited", "comment_deleted"]);

export function ActivitySection({ task }: { task: TaskDetail }) {
  const [filter, setFilter] = useState<Filter>("all");
  const items: TimelineItem[] = useMemo(
    () =>
      task.activity
        .filter((a) => (filter === "evidence" ? EVIDENCE_KINDS.has(a.kind) : filter === "changes" ? !EVIDENCE_KINDS.has(a.kind) && !NOISE_KINDS.has(a.kind) : true))
        .map((a) => {
          const text = describeActivity(a);
          return {
            id: a.id,
            time: a.created_at,
            tone: text.tone,
            icon: a.actor ? undefined : <Bot />,
            title: (
              <span className="font-normal text-fg-muted">
                <span className="font-medium text-fg">{a.actor?.name ?? "ContextOS automation"}</span> {text.text}
              </span>
            ),
            description: text.note,
          };
        }),
    [task.activity, filter],
  );

  return (
    <Section
      title="Activity"
      description={task.activity.length >= 200 ? "Showing the latest 200 entries." : "Every change to this task, newest first."}
      actions={
        <SegmentedControl<Filter>
          aria-label="Activity filter"
          value={filter}
          onChange={setFilter}
          options={[
            { value: "all", label: "All" },
            { value: "changes", label: "Changes" },
            { value: "evidence", label: "Evidence" },
          ]}
        />
      }
    >
      <Timeline items={items} dense timeFormat="relative" aria-label="Task activity" emptyLabel={filter === "all" ? "No activity recorded." : "No matching activity."} />
    </Section>
  );
}

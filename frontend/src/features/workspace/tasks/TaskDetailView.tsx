/**
 * Everything about one task, shared by the board drawer and the full task page: header and primary
 * actions, tabbed sections (details, security context, fix & verify, relations, discussion,
 * activity) and the properties panel.
 */
import { useState } from "react";
import { TabPanel, Tabs } from "@/components/ui";
import { useAuth } from "@/features/auth/AuthProvider";
import { cn } from "@/lib/format";
import { LINK_KINDS, type TaskDetail } from "../types";
import { TaskHeader } from "./TaskHeader";
import { TaskProperties } from "./TaskProperties";
import { ActivitySection } from "./sections/ActivitySection";
import { AttachmentsSection } from "./sections/AttachmentsSection";
import { CommentsSection } from "./sections/CommentsSection";
import { DetailsSection } from "./sections/DetailsSection";
import { FixAttemptsSection } from "./sections/FixAttemptsSection";
import { LinksSection } from "./sections/LinksSection";
import { RelationsSection } from "./sections/RelationsSection";
import { SecurityContextSection } from "./sections/SecurityContextSection";
import { VerificationSection } from "./sections/VerificationSection";
import { useWorkflowConflicts } from "./useWorkflowConflicts";

export type TaskTab = "details" | "security" | "fix" | "relations" | "discussion" | "activity";

export function TaskDetailView({ task, variant }: { task: TaskDetail; variant: "page" | "drawer" }) {
  const { can } = useAuth();
  const canWrite = can("write") && task.archived_at === null;
  const [tab, setTab] = useState<TaskTab>("details");
  const { report, dialog } = useWorkflowConflicts();
  const linkCount = LINK_KINDS.reduce((n, k) => n + (task.links[k]?.length ?? 0), 0);

  const tabs = [
    { value: "details", label: "Details" },
    { value: "security", label: "Security context", count: task.refs.length },
    { value: "fix", label: "Fix & verify", count: task.fix_attempts.length + task.verification_runs.length + linkCount },
    { value: "relations", label: "Relations", count: task.subtasks.length + task.blocked_by.length + task.blocking.length },
    { value: "discussion", label: "Discussion", count: task.comments.length },
    { value: "activity", label: "Activity" },
  ];

  return (
    <div className={cn(variant === "drawer" ? "px-5 py-4" : "")}>
      <TaskHeader task={task} canWrite={can("write")} />
      <div className={cn("mt-5 grid gap-5", variant === "page" ? "lg:grid-cols-[minmax(0,1fr)_300px]" : "md:grid-cols-[minmax(0,1fr)_260px]")}>
        <div className="min-w-0">
          <Tabs value={tab} onValueChange={(v) => setTab(v as TaskTab)} tabs={tabs}>
            <TabPanel value="details" className="space-y-4 pt-4">
              <DetailsSection task={task} canWrite={canWrite} />
              <AttachmentsSection task={task} canWrite={canWrite} />
            </TabPanel>
            <TabPanel value="security" className="pt-4">
              <SecurityContextSection task={task} canWrite={canWrite} />
            </TabPanel>
            <TabPanel value="fix" className="space-y-4 pt-4">
              <VerificationSection task={task} canWrite={canWrite} />
              <FixAttemptsSection task={task} canWrite={canWrite} />
              <LinksSection task={task} canWrite={canWrite} />
            </TabPanel>
            <TabPanel value="relations" className="pt-4">
              <RelationsSection task={task} canWrite={canWrite} />
            </TabPanel>
            <TabPanel value="discussion" className="pt-4">
              <CommentsSection task={task} canWrite={canWrite} />
            </TabPanel>
            <TabPanel value="activity" className="pt-4">
              <ActivitySection task={task} />
            </TabPanel>
          </Tabs>
        </div>
        <aside aria-label="Task properties" className={cn("min-w-0", variant === "page" ? "lg:sticky lg:top-0 lg:self-start" : "md:order-none -order-1")}>
          <div className="panel px-3 py-1.5">
            <TaskProperties task={task} canWrite={canWrite} report={report} />
          </div>
        </aside>
      </div>
      {dialog}
    </div>
  );
}

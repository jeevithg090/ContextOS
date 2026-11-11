/** Vocabulary for column configuration: status keys, automation triggers and their explanations. */
import { STATUS_KEY_LABELS } from "../analytics/taskMeta";
import { AUTOMATION_TRIGGERS, STATUS_KEYS, type AutomationTrigger, type StatusKey } from "../types";

export const AUTOMATION_TRIGGER_META: Record<AutomationTrigger, { label: string; description: string }> = {
  pr_linked: { label: "A pull request is linked", description: "Fires when a pull request link is added to a task in this column." },
  verification_passed: { label: "Verification passes", description: "Fires when a verification run recorded on the task passes." },
  verification_failed: { label: "Verification fails", description: "Fires when a verification run recorded on the task fails or errors." },
  fix_attempt_started: { label: "A fix attempt starts", description: "Fires when a fix attempt is recorded for the task." },
};

export const automationTriggerLabel = (trigger: string) => AUTOMATION_TRIGGER_META[trigger as AutomationTrigger]?.label ?? trigger;

export const STATUS_KEY_OPTIONS: Array<{ value: StatusKey; label: string }> = STATUS_KEYS.map((key) => ({ value: key, label: STATUS_KEY_LABELS[key] }));

export { AUTOMATION_TRIGGERS };

/**
 * The replay player: playback controls, the recomputed risk track with scrubber, the ordered step
 * list and the detail of the current step. Answers "what exactly happened, in what order, and what
 * did ContextOS decide at each point?".
 */
import { ChevronLeft, ChevronRight, Info } from "lucide-react";
import { Button, EmptyState } from "@/components/ui";
import type { Replay } from "../types";
import { PlayerControls } from "./PlayerControls";
import { RiskTrack } from "./RiskTrack";
import { StepDetail } from "./StepDetail";
import { StepList } from "./StepList";
import { usePlayer } from "./usePlayer";

export interface ReplayPlayerProps {
  replay: Replay;
  /** Window-local index to start at (e.g. the ?decision= step). */
  initialIndex: number;
  onWindow: (offset: number) => void;
  keyboard: boolean;
}

export function ReplayPlayer({ replay, initialIndex, onWindow, keyboard }: ReplayPlayerProps) {
  const steps = replay.steps;
  const player = usePlayer(steps.length, { initialIndex, keyboard });

  if (steps.length === 0) {
    return (
      <EmptyState
        icon={<Info className="h-5 w-5" />}
        title="Nothing recorded for this session yet"
        description="Steps appear here as the integration reports events for this session."
      />
    );
  }
  const step = steps[player.index];
  const windowed = replay.offset > 0 || replay.truncated;

  return (
    <div className="space-y-4">
      <div className="panel space-y-3 p-4">
        <PlayerControls player={player} count={steps.length} position={step.index + 1} total={replay.total_steps} />
        <RiskTrack steps={steps} index={player.index} onSeek={player.seek} />
        {windowed && (
          <div className="flex flex-wrap items-center justify-between gap-2 border-t border-border pt-3 text-xs text-fg-muted">
            <span>
              Showing steps {replay.offset + 1}–{replay.offset + steps.length} of {replay.total_steps}. Risk is still recomputed from the very first step.
            </span>
            <span className="flex gap-2">
              <Button size="xs" variant="outline" icon={<ChevronLeft className="h-3 w-3" aria-hidden />} disabled={replay.offset === 0} onClick={() => onWindow(Math.max(0, replay.offset - replay.limit))}>
                Earlier steps
              </Button>
              <Button size="xs" variant="outline" disabled={!replay.truncated} onClick={() => onWindow(replay.offset + replay.limit)}>
                Later steps <ChevronRight className="h-3 w-3" aria-hidden />
              </Button>
            </span>
          </div>
        )}
      </div>
      <div className="grid gap-4 lg:grid-cols-[minmax(0,5fr)_minmax(0,7fr)]">
        <section className="panel min-w-0" aria-label="Steps">
          <div className="flex items-center justify-between border-b border-border px-3 py-2">
            <h2 className="text-[13px] font-semibold text-fg">Recorded steps</h2>
            <span className="text-2xs text-fg-faint">{replay.decision_steps} with a policy decision</span>
          </div>
          <StepList steps={steps} index={player.index} onSelect={player.seek} />
        </section>
        <section className="panel min-w-0" aria-live={player.playing ? "off" : "polite"}>
          <StepDetail step={step} sessionId={replay.session.id} total={replay.total_steps} />
        </section>
      </div>
      <p className="text-2xs text-fg-faint">
        {replay.basis} {replay.risk_note}
      </p>
    </div>
  );
}

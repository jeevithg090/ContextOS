import { Pause, Play, SkipBack, SkipForward, StepBack, StepForward } from "lucide-react";
import { IconButton, Kbd } from "@/components/ui";
import { SegmentedControl } from "@/components/data";
import { cn } from "@/lib/format";
import { SPEEDS, type Player, type Speed } from "./usePlayer";

export function PlayerControls({ player, count, position, total }: { player: Player; count: number; position: number; total: number }) {
  const atStart = player.index <= 0;
  const atEnd = player.index >= count - 1;
  return (
    <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
      <div className="flex items-center gap-0.5" role="group" aria-label="Playback">
        <IconButton label="First step (Home)" onClick={() => player.seek(0)} disabled={atStart} className="disabled:opacity-40">
          <SkipBack className="h-4 w-4" aria-hidden />
        </IconButton>
        <IconButton label="Previous step (←)" onClick={player.prev} disabled={atStart} className="disabled:opacity-40">
          <StepBack className="h-4 w-4" aria-hidden />
        </IconButton>
        <button
          type="button"
          onClick={player.toggle}
          aria-label={player.playing ? "Pause (space)" : "Play (space)"}
          aria-pressed={player.playing}
          title={player.playing ? "Pause (space)" : "Play (space)"}
          className={cn(
            "mx-1 inline-flex h-8 w-8 items-center justify-center rounded-full transition-colors",
            player.playing ? "bg-accent text-accent-fg hover:bg-accent-strong" : "border border-border-strong bg-surface-2 text-fg hover:bg-surface-3",
          )}
        >
          {player.playing ? <Pause className="h-4 w-4" aria-hidden /> : <Play className="ml-0.5 h-4 w-4" aria-hidden />}
        </button>
        <IconButton label="Next step (→)" onClick={player.next} disabled={atEnd} className="disabled:opacity-40">
          <StepForward className="h-4 w-4" aria-hidden />
        </IconButton>
        <IconButton label="Last step (End)" onClick={() => player.seek(count - 1)} disabled={atEnd} className="disabled:opacity-40">
          <SkipForward className="h-4 w-4" aria-hidden />
        </IconButton>
      </div>
      <SegmentedControl<string>
        aria-label="Playback speed"
        value={String(player.speed)}
        onChange={(v) => player.setSpeed(Number(v) as Speed)}
        options={SPEEDS.map((s) => ({ value: String(s), label: `${s}×` }))}
      />
      <div className="num text-xs text-fg-muted" aria-live="polite">
        Step <span className="font-medium text-fg">{position}</span> of {total}
      </div>
      <div className="ml-auto hidden items-center gap-1.5 text-2xs text-fg-faint md:flex">
        <Kbd>←</Kbd>
        <Kbd>→</Kbd> step <Kbd>Space</Kbd> play/pause <Kbd>Home</Kbd>
        <Kbd>End</Kbd>
      </div>
    </div>
  );
}

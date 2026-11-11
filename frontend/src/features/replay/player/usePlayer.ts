/**
 * Playback state for the replay player: current step, play/pause with speed, and keyboard control
 * (← / → step, space play/pause, Home / End). Keys are ignored while typing in a form field or when a
 * dialog has focus, so the shortcuts never fight with inputs.
 */
import { useCallback, useEffect, useState } from "react";

export const SPEEDS = [0.5, 1, 2, 4] as const;
export type Speed = (typeof SPEEDS)[number];
const BASE_INTERVAL_MS = 1200;

export function clampIndex(index: number, count: number): number {
  if (count <= 0) return 0;
  return Math.min(Math.max(0, Math.round(index)), count - 1);
}

export function intervalFor(speed: Speed): number {
  return Math.round(BASE_INTERVAL_MS / speed);
}

function isTypingTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false;
  const tag = target.tagName;
  if (tag === "INPUT") return (target as HTMLInputElement).type !== "range";
  return tag === "TEXTAREA" || tag === "SELECT" || target.isContentEditable || Boolean(target.closest("[role=dialog]"));
}

export interface Player {
  index: number;
  playing: boolean;
  speed: Speed;
  seek: (index: number) => void;
  next: () => void;
  prev: () => void;
  toggle: () => void;
  setSpeed: (speed: Speed) => void;
}

export function usePlayer(count: number, { initialIndex = 0, keyboard = true }: { initialIndex?: number; keyboard?: boolean } = {}): Player {
  const [index, setIndex] = useState(() => clampIndex(initialIndex, count));
  const [playing, setPlaying] = useState(false);
  const [speed, setSpeed] = useState<Speed>(1);

  useEffect(() => {
    setIndex((i) => clampIndex(i, count));
  }, [count]);
  useEffect(() => {
    setIndex(clampIndex(initialIndex, count));
    setPlaying(false);
    // Only a new focus target (e.g. ?decision=) moves the playhead; new steps appended by live
    // updates must not.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [initialIndex]);

  const seek = useCallback((i: number) => setIndex(clampIndex(i, count)), [count]);
  const next = useCallback(() => setIndex((i) => clampIndex(i + 1, count)), [count]);
  const prev = useCallback(() => setIndex((i) => clampIndex(i - 1, count)), [count]);
  const toggle = useCallback(() => {
    setPlaying((p) => {
      if (!p) setIndex((i) => (i >= count - 1 ? 0 : i)); // replay from the start once at the end
      return !p;
    });
  }, [count]);

  useEffect(() => {
    if (!playing) return;
    if (index >= count - 1) {
      setPlaying(false);
      return;
    }
    const timer = window.setTimeout(() => setIndex((i) => clampIndex(i + 1, count)), intervalFor(speed));
    return () => window.clearTimeout(timer);
  }, [playing, index, count, speed]);

  useEffect(() => {
    if (!keyboard) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.defaultPrevented || e.metaKey || e.ctrlKey || e.altKey || isTypingTarget(e.target)) return;
      if (e.key === "ArrowRight") next();
      else if (e.key === "ArrowLeft") prev();
      else if (e.key === "Home") seek(0);
      else if (e.key === "End") seek(count - 1);
      else if (e.key === " " || e.key === "Spacebar") {
        if (e.target instanceof HTMLButtonElement) return; // let the focused button handle space itself
        toggle();
      } else return;
      e.preventDefault();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [keyboard, next, prev, seek, toggle, count]);

  return { index, playing, speed, seek, next, prev, toggle, setSpeed };
}

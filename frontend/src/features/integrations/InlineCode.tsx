/** Renders `backticked` spans of server-provided plain text as inline code (no other markup). */
export function InlineCode({ text }: { text: string }) {
  const parts = text.split(/(`[^`\n]+`)/g).map((part, i) =>
    part.length > 2 && part.startsWith("`") && part.endsWith("`") ? (
      <code key={i} className="rounded bg-surface-3 px-1 font-mono text-[0.92em] text-fg">
        {part.slice(1, -1)}
      </code>
    ) : (
      part
    ),
  );
  return <>{parts}</>;
}

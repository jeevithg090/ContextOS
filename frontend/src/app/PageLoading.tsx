/** Suspense fallback while a page's code chunk downloads: a page-shaped skeleton, announced politely. */
import { Skeleton } from "@/components/ui";

export function PageLoading({ label }: { label?: string }) {
  return (
    <div role="status" aria-live="polite" aria-busy="true" className="animate-fade-in">
      <span className="sr-only">{label ? `Loading ${label}…` : "Loading page…"}</span>
      <div className="space-y-2 pb-5" aria-hidden>
        <Skeleton className="h-3 w-28" />
        <Skeleton className="h-6 w-64" />
        <Skeleton className="h-3.5 w-[min(520px,80%)]" />
      </div>
      <div className="panel space-y-2 p-4" aria-hidden>
        {Array.from({ length: 6 }).map((_, i) => (
          <Skeleton key={i} className="h-8 w-full" />
        ))}
      </div>
    </div>
  );
}

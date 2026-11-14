/**
 * Core ContextOS UI primitives. Import from "@/components/ui".
 * Style rules: semantic tokens only, 4px spacing grid, 13.5px base, hairline borders,
 * restrained colour (status colour carries meaning — never decoration).
 */
import { cloneElement, forwardRef, isValidElement, type ButtonHTMLAttributes, type HTMLAttributes, type InputHTMLAttributes, type ReactNode, type SelectHTMLAttributes, type TextareaHTMLAttributes } from "react";
import { Loader2 } from "lucide-react";
import { cn } from "@/lib/format";
import { TONE_CLASSES, type Tone } from "@/lib/domain";

/* ----------------------------------------------------------------------------- Button */

type ButtonVariant = "primary" | "secondary" | "ghost" | "danger" | "outline";
type ButtonSize = "xs" | "sm" | "md";

const BUTTON_VARIANTS: Record<ButtonVariant, string> = {
  primary: "bg-accent text-accent-fg hover:bg-accent-strong font-medium",
  secondary: "bg-surface-3 text-fg hover:bg-surface-3/70 border border-border-strong",
  outline: "border border-border-strong text-fg hover:bg-surface-2",
  ghost: "text-fg-muted hover:text-fg hover:bg-surface-2",
  danger: "bg-danger/15 text-danger border border-danger/30 hover:bg-danger/25",
};
const BUTTON_SIZES: Record<ButtonSize, string> = {
  xs: "h-6 px-2 text-2xs gap-1",
  sm: "h-7 px-2.5 text-xs gap-1.5 touch:h-9",
  md: "h-8 px-3 text-[13px] gap-2 touch:h-10",
};

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  loading?: boolean;
  icon?: ReactNode;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(function Button(
  { variant = "secondary", size = "md", loading, icon, className, children, disabled, type = "button", ...rest },
  ref,
) {
  return (
    <button
      ref={ref}
      type={type}
      disabled={disabled || loading}
      className={cn(
        "inline-flex select-none items-center justify-center whitespace-nowrap rounded transition-colors duration-100 disabled:cursor-not-allowed disabled:opacity-50",
        BUTTON_VARIANTS[variant],
        BUTTON_SIZES[size],
        className,
      )}
      {...rest}
    >
      {loading ? <Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden /> : icon}
      {children}
    </button>
  );
});

export function IconButton({ label, className, children, ...rest }: ButtonHTMLAttributes<HTMLButtonElement> & { label: string }) {
  return (
    <button
      type="button"
      aria-label={label}
      title={label}
      className={cn("inline-flex h-7 w-7 shrink-0 items-center justify-center rounded text-fg-muted transition-colors hover:bg-surface-2 hover:text-fg touch:h-10 touch:w-10", className)}
      {...rest}
    >
      {children}
    </button>
  );
}

/* ----------------------------------------------------------------------------- Badge / Tone */

export function Badge({ tone = "neutral", children, className, dot = false, title }: { tone?: Tone; children: ReactNode; className?: string; dot?: boolean; title?: string }) {
  const t = TONE_CLASSES[tone];
  return (
    <span
      title={title}
      className={cn("inline-flex h-5 items-center gap-1.5 whitespace-nowrap rounded border px-1.5 text-2xs font-medium", t.text, t.bg, t.border, className)}
    >
      {dot && <span className={cn("h-1.5 w-1.5 rounded-full", t.dot)} aria-hidden />}
      {children}
    </span>
  );
}

export function StatusDot({ tone = "neutral", pulse = false, className }: { tone?: Tone; pulse?: boolean; className?: string }) {
  return <span className={cn("inline-block h-2 w-2 shrink-0 rounded-full", TONE_CLASSES[tone].dot, pulse && "animate-pulse-dot", className)} aria-hidden />;
}

/* ----------------------------------------------------------------------------- Card */

export function Card({ className, children, ...rest }: HTMLAttributes<HTMLDivElement>) {
  return (
    <div className={cn("panel", className)} {...rest}>
      {children}
    </div>
  );
}

export function CardHeader({ title, description, actions, className }: { title: ReactNode; description?: ReactNode; actions?: ReactNode; className?: string }) {
  return (
    <div className={cn("flex items-start justify-between gap-3 border-b border-border px-4 py-3", className)}>
      <div className="min-w-0">
        <h3 className="text-[13px] font-semibold text-fg">{title}</h3>
        {description && <p className="mt-0.5 text-xs text-fg-muted">{description}</p>}
      </div>
      {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
    </div>
  );
}

export function CardBody({ className, children }: { className?: string; children: ReactNode }) {
  return <div className={cn("p-4", className)}>{children}</div>;
}

/* ----------------------------------------------------------------------------- Page header */

export function PageHeader({ title, description, actions, eyebrow }: { title: ReactNode; description?: ReactNode; actions?: ReactNode; eyebrow?: ReactNode }) {
  return (
    <header className="flex flex-wrap items-end justify-between gap-4 pb-5">
      <div className="min-w-0">
        {eyebrow && <div className="label-caps mb-1.5">{eyebrow}</div>}
        <h1 className="break-words text-xl font-semibold text-fg">{title}</h1>
        {/* break-words: descriptions can carry unbroken hashes or URLs (context receipts) that would widen the page.
            A <div>, not a <p>: some pages pass block content (inline stats) as the description. */}
        {description && <div className="mt-1 max-w-3xl break-words text-[13px] text-fg-muted">{description}</div>}
      </div>
      {actions && <div className="flex items-center gap-2">{actions}</div>}
    </header>
  );
}

/* ----------------------------------------------------------------------------- States */

export function EmptyState({ icon, title, description, action, className }: { icon?: ReactNode; title: string; description?: ReactNode; action?: ReactNode; className?: string }) {
  return (
    <div className={cn("flex flex-col items-center justify-center px-6 py-14 text-center", className)}>
      {icon && <div className="mb-3 flex h-10 w-10 items-center justify-center rounded-lg border border-border bg-surface-2 text-fg-muted">{icon}</div>}
      <div className="text-[13px] font-medium text-fg">{title}</div>
      {description && <div className="mt-1 max-w-md text-xs text-fg-muted">{description}</div>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}

export function ErrorState({ error, onRetry, className }: { error: unknown; onRetry?: () => void; className?: string }) {
  const message = error instanceof Error ? error.message : "Something went wrong.";
  return (
    <div role="alert" className={cn("flex flex-col items-center justify-center px-6 py-12 text-center", className)}>
      <div className="text-[13px] font-medium text-danger">Couldn’t load this view</div>
      <div className="mt-1 max-w-md text-xs text-fg-muted">{message}</div>
      {onRetry && (
        <Button size="sm" variant="outline" className="mt-4" onClick={onRetry}>
          Retry
        </Button>
      )}
    </div>
  );
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={cn("animate-pulse rounded bg-surface-3/70", className)} aria-hidden />;
}

export function LoadingRows({ rows = 5 }: { rows?: number }) {
  return (
    <div className="space-y-2 p-4" aria-busy="true" aria-label="Loading">
      {Array.from({ length: rows }).map((_, i) => (
        <Skeleton key={i} className="h-8 w-full" />
      ))}
    </div>
  );
}

export function Spinner({ className }: { className?: string }) {
  return <Loader2 className={cn("h-4 w-4 animate-spin text-fg-muted", className)} aria-label="Loading" />;
}

/* ----------------------------------------------------------------------------- Form controls */

// Sizing (h-/w-/px-/py-/text-size) and colours can be overridden through `className`: cn() lets the
// later class of a conflicting group win, so `<Input className="h-7 text-xs" />` needs no "!".

const CONTROL = "w-full rounded border border-border-strong bg-surface-2 px-2.5 text-[13px] text-fg placeholder:text-fg-faint transition-colors focus:border-accent/60 focus:outline-none focus:ring-2 focus:ring-accent/25 focus-visible:outline-none aria-[invalid=true]:border-danger/60 disabled:opacity-60 touch:text-base";

export const Input = forwardRef<HTMLInputElement, InputHTMLAttributes<HTMLInputElement>>(function Input({ className, ...rest }, ref) {
  return <input ref={ref} className={cn(CONTROL, "h-8 touch:h-10", className)} {...rest} />;
});

export const Textarea = forwardRef<HTMLTextAreaElement, TextareaHTMLAttributes<HTMLTextAreaElement>>(function Textarea({ className, ...rest }, ref) {
  return <textarea ref={ref} className={cn(CONTROL, "min-h-[80px] py-2 leading-relaxed", className)} {...rest} />;
});

export const Select = forwardRef<HTMLSelectElement, SelectHTMLAttributes<HTMLSelectElement>>(function Select({ className, children, ...rest }, ref) {
  return (
    // pr-7 comes after className: the right padding reserves room for the chevron and must survive
    // a caller's px-* override (cn() resolves conflicts so the last class wins).
    <select ref={ref} className={cn(CONTROL, "h-8 touch:h-10 appearance-none bg-[length:12px] bg-[right_8px_center] bg-no-repeat", className, "pr-7")} style={{ backgroundImage: "url(\"data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 12 12' fill='none' stroke='%23929bab' stroke-width='1.5'%3E%3Cpath d='M3 4.5 6 7.5 9 4.5'/%3E%3C/svg%3E\")" }} {...rest}>
      {children}
    </select>
  );
});

export function Field({ label, hint, error, children, htmlFor, className }: { label: string; hint?: ReactNode; error?: string | null; children: ReactNode; htmlFor?: string; className?: string }) {
  // With an id to anchor on, the hint or error is wired to the control (aria-describedby) and an
  // error marks it invalid, so screen readers announce the message with the field.
  const messageId = htmlFor ? `${htmlFor}-${error ? "error" : "hint"}` : undefined;
  const hasMessage = !!(error || hint);
  // Layout wrappers (a plain <div> around an input and its button) are left alone; the page wires
  // the inner control itself with `fieldDescription()`.
  const isControl = isValidElement(children) && (typeof children.type !== "string" || ["input", "select", "textarea"].includes(children.type));
  const control =
    htmlFor && isControl && isValidElement<Record<string, unknown>>(children)
      ? cloneElement(children, {
          "aria-describedby": hasMessage ? [children.props["aria-describedby"], messageId].filter(Boolean).join(" ") : children.props["aria-describedby"],
          "aria-invalid": error ? true : children.props["aria-invalid"],
        })
      : children;
  return (
    <div className={cn("space-y-1.5", className)}>
      <label htmlFor={htmlFor} className="block text-xs font-medium text-fg-muted">
        {label}
      </label>
      {control}
      {error ? (
        <p id={messageId} className="text-2xs text-danger">
          {error}
        </p>
      ) : hint ? (
        <p id={messageId} className="text-2xs text-fg-faint">
          {hint}
        </p>
      ) : null}
    </div>
  );
}

/** aria props for a control nested inside a Field's layout wrapper (ids match what Field renders). */
export function fieldDescription(htmlFor: string, { hint, error }: { hint?: ReactNode; error?: string | null }) {
  return {
    "aria-describedby": error ? `${htmlFor}-error` : hint ? `${htmlFor}-hint` : undefined,
    "aria-invalid": error ? true : undefined,
  } as const;
}

export function Checkbox({ label, checked, onChange, disabled }: { label: ReactNode; checked: boolean; onChange: (v: boolean) => void; disabled?: boolean }) {
  return (
    <label className={cn("inline-flex cursor-pointer items-center gap-2 text-[13px] text-fg", disabled && "cursor-not-allowed opacity-60")}>
      <input type="checkbox" className="h-3.5 w-3.5 touch:h-5 touch:w-5 rounded border-border-strong bg-surface-2 accent-[rgb(var(--accent))]" checked={checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)} />
      {label}
    </label>
  );
}

/* ----------------------------------------------------------------------------- Table */

export function Table({ className, children }: { className?: string; children: ReactNode }) {
  return (
    <div className={cn("relative overflow-x-auto", className)}>
      <table className="w-full border-collapse text-left text-[13px]">{children}</table>
    </div>
  );
}
export function THead({ children }: { children: ReactNode }) {
  return <thead className="border-b border-border text-2xs uppercase tracking-[0.06em] text-fg-faint">{children}</thead>;
}
export function TH({ children, className }: { children?: ReactNode; className?: string }) {
  return <th className={cn("whitespace-nowrap px-4 py-2 font-medium", className)}>{children}</th>;
}
export function TR({ children, className, onClick, selected }: { children: ReactNode; className?: string; onClick?: () => void; selected?: boolean }) {
  return (
    <tr
      onClick={onClick}
      className={cn("border-b border-border/70 last:border-0", onClick && "cursor-pointer hover:bg-surface-2/70", selected && "bg-accent/[0.06]", className)}
    >
      {children}
    </tr>
  );
}
export function TD({ children, className, colSpan }: { children?: ReactNode; className?: string; colSpan?: number }) {
  return (
    <td colSpan={colSpan} className={cn("px-4 py-2.5 align-middle", className)}>
      {children}
    </td>
  );
}

/* ----------------------------------------------------------------------------- Misc */

export function Kbd({ children }: { children: ReactNode }) {
  return <kbd className="rounded border border-border-strong bg-surface-2 px-1 font-mono text-2xs text-fg-muted">{children}</kbd>;
}

export function Mono({ children, className, title }: { children: ReactNode; className?: string; title?: string }) {
  return (
    <span title={title} className={cn("font-mono text-xs text-fg-muted", className)}>
      {children}
    </span>
  );
}

export function Stat({ label, value, hint, tone, className }: { label: string; value: ReactNode; hint?: ReactNode; tone?: Tone; className?: string }) {
  return (
    <div className={cn("min-w-0", className)}>
      <div className="label-caps">{label}</div>
      <div className={cn("num mt-1 text-2xl font-semibold leading-none", tone ? TONE_CLASSES[tone].text : "text-fg")}>{value}</div>
      {hint && <div className="mt-1.5 text-xs text-fg-muted">{hint}</div>}
    </div>
  );
}

export function Divider({ className }: { className?: string }) {
  return <div className={cn("h-px w-full bg-border", className)} />;
}

export function KeyValue({ items, className }: { items: Array<{ label: string; value: ReactNode }>; className?: string }) {
  return (
    <dl className={cn("grid grid-cols-[minmax(110px,max-content)_1fr] gap-x-4 gap-y-2 text-[13px]", className)}>
      {items.map((item) => (
        <div key={item.label} className="contents">
          <dt className="text-fg-faint">{item.label}</dt>
          <dd className="min-w-0 break-words text-fg">{item.value}</dd>
        </div>
      ))}
    </dl>
  );
}

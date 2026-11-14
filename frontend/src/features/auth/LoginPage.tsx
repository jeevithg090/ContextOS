import { useState, type FormEvent } from "react";
import { Navigate, useLocation, useNavigate } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "@/lib/api";
import { Eye, EyeOff } from "lucide-react";
import { Button, Field, fieldDescription, IconButton, Input } from "@/components/ui";
import { ThemeMenu } from "@/components/layout/ThemeMenu";
import { useAuth, type Me } from "./AuthProvider";

export function LoginPage() {
  const { me } = useAuth();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const location = useLocation();
  const setup = useQuery({ queryKey: ["auth", "setup-status"], queryFn: () => api.get<{ needs_setup: boolean }>("/auth/setup-status") });
  const [form, setForm] = useState({ email: "", password: "", name: "", organization_name: "" });
  const [error, setError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<FieldErrors>({});
  const [showPassword, setShowPassword] = useState(false);
  const [busy, setBusy] = useState(false);

  if (me) return <Navigate to={(location.state as { from?: string })?.from ?? "/"} replace />;
  const needsSetup = setup.data?.needs_setup;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    const problems = validate(form, !!needsSetup);
    setFieldErrors(problems);
    if (Object.keys(problems).length > 0) {
      const first = FIELD_ORDER.find(([field]) => problems[field]);
      if (first) document.getElementById(first[1])?.focus();
      return;
    }
    setBusy(true);
    setError(null);
    try {
      const result = needsSetup
        ? await api.post<Me>("/auth/setup", form)
        : await api.post<Me>("/auth/login", { email: form.email, password: form.password });
      qc.setQueryData(["auth", "me"], result);
      navigate("/", { replace: true });
    } catch (err) {
      setError(err instanceof ApiError ? err.message : "Sign-in failed");
    } finally {
      setBusy(false);
    }
  };

  const set = (key: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement>) => {
    setForm({ ...form, [key]: e.target.value });
    // Clear a field's message as soon as the user starts correcting it.
    if (fieldErrors[key]) setFieldErrors({ ...fieldErrors, [key]: undefined });
  };

  return (
    <main className="relative flex min-h-full items-center justify-center px-4 py-16">
      <ThemeMenu className="absolute right-4 top-4" />
      <div className="w-full max-w-[380px] animate-slide-up">
        <div className="mb-8 flex items-center gap-2.5">
          <svg viewBox="0 0 32 32" className="h-7 w-7" aria-hidden>
            <path d="M9 11.5 16 7l7 4.5v9L16 25l-7-4.5z" fill="none" stroke="rgb(var(--accent))" strokeWidth="2.2" strokeLinejoin="round" />
            <circle cx="16" cy="16" r="2.6" fill="rgb(var(--accent))" />
          </svg>
          <span className="text-lg font-semibold tracking-tight">ContextOS</span>
        </div>
        <h1 className="text-xl font-semibold">{needsSetup ? "Create your organisation" : "Sign in"}</h1>
        <p className="mt-1 text-[13px] text-fg-muted">
          {needsSetup
            ? "First run: this creates the organisation and its owner account on this ContextOS server."
            : "Security, trust and provenance for your AI agents."}
        </p>
        <form onSubmit={submit} noValidate className="panel mt-6 space-y-4 p-5">
          {needsSetup && (
            <>
              <Field label="Organisation name" htmlFor="org" error={fieldErrors.organization_name}>
                <Input id="org" required value={form.organization_name} onChange={set("organization_name")} placeholder="Acme AI" />
              </Field>
              <Field label="Your name" htmlFor="name" error={fieldErrors.name}>
                <Input id="name" required autoComplete="name" value={form.name} onChange={set("name")} />
              </Field>
            </>
          )}
          <Field label="Email" htmlFor="email" error={fieldErrors.email}>
            <Input id="email" type="email" autoComplete="email" required value={form.email} onChange={set("email")} />
          </Field>
          <Field label="Password" htmlFor="password" hint={needsSetup ? "At least 10 characters." : undefined} error={fieldErrors.password}>
            <div className="relative">
              <Input
                id="password"
                type={showPassword ? "text" : "password"}
                autoComplete={needsSetup ? "new-password" : "current-password"}
                required
                minLength={needsSetup ? 10 : 1}
                value={form.password}
                onChange={set("password")}
                className="pr-9"
                {...fieldDescription("password", { hint: needsSetup ? "At least 10 characters." : undefined, error: fieldErrors.password })}
              />
              <IconButton
                label={showPassword ? "Hide password" : "Show password"}
                aria-pressed={showPassword}
                onClick={() => setShowPassword((v) => !v)}
                className="absolute right-0.5 top-1/2 -translate-y-1/2"
              >
                {showPassword ? <EyeOff className="h-4 w-4" aria-hidden /> : <Eye className="h-4 w-4" aria-hidden />}
              </IconButton>
            </div>
          </Field>
          {error && (
            <div role="alert" className="rounded border border-danger/30 bg-danger/10 px-3 py-2 text-xs text-danger">
              {error}
            </div>
          )}
          <Button type="submit" variant="primary" className="w-full" loading={busy}>
            {needsSetup ? "Create organisation" : "Sign in"}
          </Button>
        </form>
        {setup.isError && <p className="mt-4 text-xs text-danger">Cannot reach the ContextOS API.</p>}
      </div>
    </main>
  );
}

type FormState = { email: string; password: string; name: string; organization_name: string };
type FieldErrors = Partial<Record<keyof FormState, string>>;
/** Form fields in screen order, with the id of their input (the first invalid one gets focus). */
const FIELD_ORDER: [keyof FormState, string][] = [
  ["organization_name", "org"],
  ["name", "name"],
  ["email", "email"],
  ["password", "password"],
];

/** Friendly client-side checks before the request; the server still validates everything. */
function validate(form: FormState, setup: boolean): FieldErrors {
  const errors: FieldErrors = {};
  if (setup && !form.organization_name.trim()) errors.organization_name = "Enter a name for your organisation.";
  if (setup && !form.name.trim()) errors.name = "Enter your name.";
  if (!form.email.trim()) errors.email = "Enter your email address.";
  else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(form.email.trim())) errors.email = "Enter a valid email address, like name@example.com.";
  if (!form.password) errors.password = "Enter your password.";
  else if (setup && form.password.length < 10) errors.password = "Use at least 10 characters.";
  return errors;
}

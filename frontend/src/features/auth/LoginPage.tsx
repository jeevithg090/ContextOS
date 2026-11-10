import { useState, type FormEvent } from "react";
import { Navigate, useLocation, useNavigate } from "react-router-dom";
import { useQuery, useQueryClient } from "@tanstack/react-query";
import { api, ApiError } from "@/lib/api";
import { Button, Field, Input } from "@/components/ui";
import { useAuth, type Me } from "./AuthProvider";

export function LoginPage() {
  const { me } = useAuth();
  const qc = useQueryClient();
  const navigate = useNavigate();
  const location = useLocation();
  const setup = useQuery({ queryKey: ["auth", "setup-status"], queryFn: () => api.get<{ needs_setup: boolean }>("/auth/setup-status") });
  const [form, setForm] = useState({ email: "", password: "", name: "", organization_name: "" });
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  if (me) return <Navigate to={(location.state as { from?: string })?.from ?? "/"} replace />;
  const needsSetup = setup.data?.needs_setup;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
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

  const set = (key: keyof typeof form) => (e: React.ChangeEvent<HTMLInputElement>) => setForm({ ...form, [key]: e.target.value });

  return (
    <div className="flex min-h-full items-center justify-center px-4 py-16">
      <div className="w-full max-w-[380px]">
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
        <form onSubmit={submit} className="mt-6 space-y-4">
          {needsSetup && (
            <>
              <Field label="Organisation name" htmlFor="org">
                <Input id="org" required value={form.organization_name} onChange={set("organization_name")} placeholder="Acme AI" />
              </Field>
              <Field label="Your name" htmlFor="name">
                <Input id="name" required value={form.name} onChange={set("name")} />
              </Field>
            </>
          )}
          <Field label="Email" htmlFor="email">
            <Input id="email" type="email" autoComplete="email" required value={form.email} onChange={set("email")} />
          </Field>
          <Field label="Password" htmlFor="password" hint={needsSetup ? "At least 10 characters." : undefined}>
            <Input id="password" type="password" autoComplete={needsSetup ? "new-password" : "current-password"} required minLength={needsSetup ? 10 : 1} value={form.password} onChange={set("password")} />
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
    </div>
  );
}

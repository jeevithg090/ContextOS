import { useEffect, useState, type FormEvent } from "react";
import { KeyRound } from "lucide-react";
import { CopyButton } from "@/components/data";
import { Button, Dialog, Field, Input, Select, useToast } from "@/components/ui";
import type { Role } from "@/lib/domain";
import { useAddMember } from "./api";
import { ROLE_META, ROLE_ORDER } from "./meta";

const PASSWORD_MIN = 10;
const EMPTY = { name: "", email: "", role: "developer" as Role, password: "" };

/** 18 characters from an unambiguous alphabet using the browser's CSPRNG. */
function generatePassword(): string {
  const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789";
  const bytes = new Uint32Array(18);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => alphabet[b % alphabet.length]).join("");
}

export function AddMemberDialog({ open, onOpenChange, isOwner }: { open: boolean; onOpenChange: (open: boolean) => void; isOwner: boolean }) {
  const toast = useToast();
  const add = useAddMember();
  const [form, setForm] = useState(EMPTY);
  const [showPassword, setShowPassword] = useState(false);

  useEffect(() => {
    if (open) {
      setForm(EMPTY);
      setShowPassword(false);
      add.reset();
    }
    // Reset only when the dialog opens.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  const passwordError = form.password && form.password.length < PASSWORD_MIN ? `At least ${PASSWORD_MIN} characters.` : null;

  const submit = (e: FormEvent) => {
    e.preventDefault();
    if (passwordError) return;
    add.mutate(
      { name: form.name.trim(), email: form.email.trim(), role: form.role, password: form.password || undefined },
      {
        onSuccess: (member) => {
          toast.success(`${member.name} added`, `${member.email} now has the ${ROLE_META[member.role].label} role.`);
          onOpenChange(false);
        },
      },
    );
  };

  const roles = ROLE_ORDER.filter((r) => isOwner || r !== "owner");

  return (
    <Dialog
      open={open}
      onOpenChange={(next) => !add.isPending && onOpenChange(next)}
      title="Add member"
      description="Give someone access to this organisation. ContextOS does not send email — share the sign-in details yourself."
      footer={
        <>
          <Button variant="ghost" size="sm" onClick={() => onOpenChange(false)} disabled={add.isPending}>
            Cancel
          </Button>
          <Button type="submit" form="add-member-form" variant="primary" size="sm" loading={add.isPending}>
            Add member
          </Button>
        </>
      }
    >
      <form id="add-member-form" onSubmit={submit} className="space-y-4">
        <div className="grid gap-4 sm:grid-cols-2">
          <Field label="Name" htmlFor="member-name">
            <Input id="member-name" required maxLength={200} value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} autoComplete="off" />
          </Field>
          <Field label="Email" htmlFor="member-email" hint="Used to sign in.">
            <Input id="member-email" type="email" required maxLength={320} value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} autoComplete="off" />
          </Field>
        </div>
        <Field label="Role" htmlFor="member-role" hint={ROLE_META[form.role].summary}>
          <Select id="member-role" value={form.role} onChange={(e) => setForm({ ...form, role: e.target.value as Role })}>
            {roles.map((r) => (
              <option key={r} value={r}>
                {ROLE_META[r].label}
              </option>
            ))}
          </Select>
        </Field>
        <Field
          label="Initial password"
          htmlFor="member-password"
          error={passwordError}
          hint="Required for a new account. If this email already has an account on this server, they are added with their existing password and this field is ignored."
        >
          <div className="flex gap-2">
            <Input
              id="member-password"
              type={showPassword ? "text" : "password"}
              value={form.password}
              maxLength={256}
              autoComplete="new-password"
              onChange={(e) => setForm({ ...form, password: e.target.value })}
              className="font-mono"
            />
            {form.password && showPassword && <CopyButton value={form.password} label="Copy initial password" className="border border-border-strong" />}
            <Button
              size="md"
              variant="outline"
              icon={<KeyRound className="h-3.5 w-3.5" aria-hidden />}
              onClick={() => {
                setForm({ ...form, password: generatePassword() });
                setShowPassword(true);
              }}
            >
              Generate
            </Button>
          </div>
        </Field>
        {add.error && (
          <p role="alert" className="rounded border border-danger/30 bg-danger/10 px-3 py-2 text-xs text-danger">
            {add.error.message}
          </p>
        )}
      </form>
    </Dialog>
  );
}

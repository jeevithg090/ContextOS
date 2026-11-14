/** Header control for the colour theme: System, Light or Dark (see src/lib/theme.ts). */
import * as DropdownMenu from "@radix-ui/react-dropdown-menu";
import { Check, Monitor, Moon, Sun } from "lucide-react";
import { cn } from "@/lib/format";
import { useTheme, type ThemePreference } from "@/lib/theme";

const OPTIONS: { value: ThemePreference; label: string; icon: typeof Sun }[] = [
  { value: "system", label: "System", icon: Monitor },
  { value: "light", label: "Light", icon: Sun },
  { value: "dark", label: "Dark", icon: Moon },
];

export function ThemeMenu({ className }: { className?: string }) {
  const { preference, resolved, setPreference } = useTheme();
  const CurrentIcon = resolved === "light" ? Sun : Moon;
  const current = OPTIONS.find((o) => o.value === preference)?.label ?? "Dark";
  return (
    <DropdownMenu.Root>
      <DropdownMenu.Trigger
        aria-label={`Colour theme: ${current}`}
        title="Colour theme"
        className={cn(
          "inline-flex h-7 w-7 items-center justify-center rounded text-fg-muted transition-colors hover:bg-surface-2 hover:text-fg data-[state=open]:bg-surface-2 data-[state=open]:text-fg touch:h-10 touch:w-10",
          className,
        )}
      >
        <CurrentIcon className="h-4 w-4" aria-hidden />
      </DropdownMenu.Trigger>
      <DropdownMenu.Portal>
        <DropdownMenu.Content
          align="end"
          sideOffset={6}
          className="z-50 min-w-[9rem] rounded-md border border-border bg-surface-2 p-1 shadow-pop animate-slide-up"
        >
          <DropdownMenu.Label className="label-caps px-2 pb-1 pt-1.5">Theme</DropdownMenu.Label>
          <DropdownMenu.RadioGroup value={preference} onValueChange={(v) => setPreference(v as ThemePreference)}>
            {OPTIONS.map(({ value, label, icon: Icon }) => (
              <DropdownMenu.RadioItem
                key={value}
                value={value}
                className="flex h-8 cursor-pointer select-none items-center gap-2 rounded px-2 text-[13px] text-fg-muted outline-none data-[highlighted]:bg-surface-3 data-[state=checked]:text-fg touch:h-10"
              >
                <Icon className="h-4 w-4" aria-hidden />
                <span className="flex-1">{label}</span>
                <DropdownMenu.ItemIndicator>
                  <Check className="h-3.5 w-3.5 text-accent" aria-hidden />
                </DropdownMenu.ItemIndicator>
              </DropdownMenu.RadioItem>
            ))}
          </DropdownMenu.RadioGroup>
        </DropdownMenu.Content>
      </DropdownMenu.Portal>
    </DropdownMenu.Root>
  );
}

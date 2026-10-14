import type { ReactNode } from "react";
import { cn } from "../../lib/cn";

export interface SectionHeaderProps {
  title: string;
  subtitle?: string;
  eyebrow?: string;
  /** Optional right-aligned content, e.g. a Button. */
  action?: ReactNode;
  className?: string;
}

export function SectionHeader({ title, subtitle, eyebrow, action, className }: SectionHeaderProps) {
  return (
    <div className={cn("flex flex-wrap items-end justify-between gap-4", className)}>
      <div className="space-y-1">
        {eyebrow && (
          <p className="text-xs font-semibold uppercase tracking-[0.18em] text-accent-cyan-bright">
            {eyebrow}
          </p>
        )}
        <h2 className="text-2xl font-semibold text-white">{title}</h2>
        {subtitle && <p className="max-w-2xl text-sm text-slate-400">{subtitle}</p>}
      </div>
      {action && <div className="shrink-0">{action}</div>}
    </div>
  );
}

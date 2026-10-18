import type { HTMLAttributes } from "react";
import { cn } from "../../lib/cn";

export interface GlassCardProps extends HTMLAttributes<HTMLDivElement> {
  /** Add a violet neon glow on hover (for interactive cards). */
  interactive?: boolean;
}

export function GlassCard({ interactive = false, className, ...props }: GlassCardProps) {
  return (
    <div
      className={cn(
        "rounded-2xl border border-white/10 bg-surface p-6 backdrop-blur-md",
        "shadow-[0_8px_30px_rgba(0,0,0,0.25)]",
        interactive &&
          "transition-all hover:border-accent/40 hover:shadow-neon focus-within:border-accent/40",
        className,
      )}
      {...props}
    />
  );
}

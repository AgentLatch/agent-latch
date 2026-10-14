import type { HTMLAttributes } from "react";
import { cn } from "../../lib/cn";

type Tone = "neutral" | "violet" | "cyan" | "high" | "medium" | "low";

export interface BadgeProps extends HTMLAttributes<HTMLSpanElement> {
  tone?: Tone;
}

const tones: Record<Tone, string> = {
  neutral: "bg-white/5 text-slate-300 border-white/10",
  violet: "bg-accent/15 text-accent border-accent/30",
  cyan: "bg-accent-cyan/15 text-accent-cyan-bright border-accent-cyan/30",
  // Risk levels
  high: "bg-risk-high/15 text-risk-high border-risk-high/30",
  medium: "bg-risk-medium/15 text-risk-medium border-risk-medium/30",
  low: "bg-risk-low/15 text-risk-low border-risk-low/30",
};

export function Badge({ tone = "neutral", className, ...props }: BadgeProps) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-xs font-medium",
        tones[tone],
        className,
      )}
      {...props}
    />
  );
}

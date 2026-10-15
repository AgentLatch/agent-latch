import { useEffect, useState } from "react";
import { GlassCard, SectionHeader } from "../ui";
import { Code, Cpu, FileCheck, GitBranch } from "../ui/icons";

interface Stage {
  title: string;
  detail: string;
  icon: typeof Code;
  items?: string[];
}

const STAGES: Stage[] = [
  {
    title: "Local workspace",
    detail: "Your code never leaves the machine",
    icon: Code,
    items: ["Python code", "Agent manifests", "Prompt templates"],
  },
  { title: "AgentLatch CLI", detail: "Static heuristics scanner", icon: Cpu },
  { title: "AST & rule engine", detail: "Parses and matches rules", icon: FileCheck },
  { title: "Audit report", detail: "CI/CD pass or fail", icon: GitBranch },
];

export function WorkflowDiagram() {
  const [active, setActive] = useState(0);

  useEffect(() => {
    const reduce = window.matchMedia?.("(prefers-reduced-motion: reduce)").matches;
    if (reduce) return;
    const id = setInterval(() => setActive((a) => (a + 1) % STAGES.length), 1400);
    return () => clearInterval(id);
  }, []);

  return (
    <section className="space-y-8">
      <SectionHeader
        eyebrow="How it works"
        title="Static scanning workflow"
        subtitle="Everything runs locally: the scanner reads your files, applies rules, and returns a pass/fail audit for CI."
      />

      <div className="flex flex-col items-stretch gap-4 lg:flex-row lg:items-center">
        {STAGES.map((stage, i) => {
          const Icon = stage.icon;
          const isActive = i === active;
          return (
            <div key={stage.title} className="flex flex-col items-stretch gap-4 lg:flex-1 lg:flex-row lg:items-center">
              <GlassCard
                className={
                  "flex-1 transition-all duration-500 " +
                  (isActive
                    ? "border-accent/50 shadow-neon"
                    : "border-white/10 opacity-80")
                }
              >
                <div className="flex items-start gap-3">
                  <span
                    className={
                      "grid h-10 w-10 shrink-0 place-items-center rounded-xl transition-colors " +
                      (isActive ? "bg-accent text-white" : "bg-white/5 text-accent")
                    }
                  >
                    <Icon className="h-5 w-5" />
                  </span>
                  <div className="min-w-0">
                    <p className="text-xs font-semibold uppercase tracking-wider text-slate-500">
                      Step {i + 1}
                    </p>
                    <h3 className="font-semibold text-white">{stage.title}</h3>
                    <p className="text-sm text-slate-400">{stage.detail}</p>
                  </div>
                </div>
                {stage.items && (
                  <ul className="mt-4 space-y-1.5">
                    {stage.items.map((item) => (
                      <li key={item} className="flex items-center gap-2 text-sm text-slate-300">
                        <span className="h-1.5 w-1.5 rounded-full bg-accent-cyan" />
                        {item}
                      </li>
                    ))}
                  </ul>
                )}
              </GlassCard>

              {i < STAGES.length - 1 && (
                <div className="flex items-center justify-center lg:w-10">
                  {/* Animated connector: horizontal on desktop, vertical on mobile. */}
                  <span className="hidden h-0.5 w-10 flow-line-x lg:block" aria-hidden="true" />
                  <span className="h-6 w-0.5 flow-line-y lg:hidden" aria-hidden="true" />
                </div>
              )}
            </div>
          );
        })}
      </div>
    </section>
  );
}

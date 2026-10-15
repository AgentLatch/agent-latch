import { GlassCard, SectionHeader } from "../ui";
import { Code, FileCheck, GitBranch, Lock } from "../ui/icons";

const CAPABILITIES = [
  {
    icon: Lock,
    title: "Local-first static analysis",
    body: "Zero data leakage. Scans run entirely offline on your machine — no code is ever uploaded.",
    tone: "text-accent bg-accent/15",
  },
  {
    icon: FileCheck,
    title: "Manifest & YAML audit",
    body: "Validates agent-manifest.yaml and prompt templates for risky tools, permissions, and auth.",
    tone: "text-accent-cyan-bright bg-accent-cyan/15",
  },
  {
    icon: Code,
    title: "AST code parsing",
    body: "Parses Python agent frameworks with an AST rule engine — no code is imported or executed.",
    tone: "text-accent bg-accent/15",
  },
  {
    icon: GitBranch,
    title: "CI/CD & pre-commit",
    body: "GitHub Actions ready, with a pre-commit hook and pass/fail thresholds for your pipeline.",
    tone: "text-accent-cyan-bright bg-accent-cyan/15",
  },
];

export function CapabilitiesGrid() {
  return (
    <section className="space-y-8">
      <SectionHeader
        eyebrow="Capabilities"
        title="Core scanner capabilities"
        subtitle="Purpose-built static checks for agentic code, mapped to the OWASP Agentic Top 10."
      />
      <div className="grid gap-5 sm:grid-cols-2">
        {CAPABILITIES.map((c) => {
          const Icon = c.icon;
          return (
            <GlassCard key={c.title} interactive className="flex gap-4">
              <span className={`grid h-12 w-12 shrink-0 place-items-center rounded-xl ${c.tone}`}>
                <Icon className="h-6 w-6" />
              </span>
              <div>
                <h3 className="font-semibold text-white">{c.title}</h3>
                <p className="mt-1 text-sm leading-relaxed text-slate-400">{c.body}</p>
              </div>
            </GlassCard>
          );
        })}
      </div>
    </section>
  );
}

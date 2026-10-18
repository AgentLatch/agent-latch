import { Badge, Button, GlassCard, SectionHeader } from "../components/ui";

const stats = [
  { label: "Projects scanned", value: "24", tone: "violet" as const },
  { label: "Open findings", value: "137", tone: "cyan" as const },
  { label: "High / critical", value: "18", tone: "high" as const },
];

const riskRows = [
  { rule: "AGENTLATCH-PY002", where: "tools.py:10", level: "high" as const, text: "Shell command injection" },
  { rule: "AGENTLATCH-AG004", where: "orchestrator.py:9", level: "medium" as const, text: "Tool writes files, no approval" },
  { rule: "AGENTLATCH-AG003", where: "tools.py:21", level: "low" as const, text: "Unfenced web content into prompt" },
];

export function Dashboard() {
  return (
    <div className="space-y-8">
      <SectionHeader
        eyebrow="Overview"
        title="Security posture"
        subtitle="Agentic risk across your connected projects, mapped to the OWASP Agentic Top 10."
        action={<Button variant="glow">New scan</Button>}
      />

      <div className="grid gap-5 sm:grid-cols-3">
        {stats.map((s) => (
          <GlassCard key={s.label} interactive>
            <p className="text-sm text-slate-400">{s.label}</p>
            <div className="mt-2 flex items-end justify-between">
              <span className="text-4xl font-semibold text-white">{s.value}</span>
              <Badge tone={s.tone}>live</Badge>
            </div>
          </GlassCard>
        ))}
      </div>

      <GlassCard>
        <SectionHeader
          title="Latest findings"
          action={<Button variant="secondary" size="sm">View all</Button>}
        />
        <div className="mt-5 divide-y divide-white/5">
          {riskRows.map((r) => (
            <div key={r.rule} className="flex items-center justify-between gap-4 py-3">
              <div className="min-w-0">
                <p className="truncate font-mono text-sm text-slate-200">{r.rule}</p>
                <p className="truncate text-xs text-slate-500">{r.text}</p>
              </div>
              <div className="flex shrink-0 items-center gap-3">
                <span className="hidden font-mono text-xs text-slate-500 sm:inline">{r.where}</span>
                <Badge tone={r.level}>{r.level}</Badge>
              </div>
            </div>
          ))}
        </div>
      </GlassCard>
    </div>
  );
}

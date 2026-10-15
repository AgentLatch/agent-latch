import { Badge, Button, GlassCard, SectionHeader } from "../components/ui";

export function Scans() {
  return (
    <div className="space-y-8">
      <SectionHeader
        eyebrow="Scans"
        title="Scan runs"
        subtitle="Static AgentLatch scans across your repositories."
        action={<Button variant="glow">Run scan</Button>}
      />
      <GlassCard>
        <div className="flex items-center justify-between gap-4">
          <div className="min-w-0">
            <p className="truncate font-mono text-sm text-slate-200">examples/vulnerable-agent</p>
            <p className="truncate text-xs text-slate-500">Last run 2 hours ago · 11 findings</p>
          </div>
          <Badge tone="high" className="shrink-0">
            4 high
          </Badge>
        </div>
      </GlassCard>
    </div>
  );
}

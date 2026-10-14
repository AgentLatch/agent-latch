import { Badge, GlassCard, SectionHeader } from "../components/ui";

export function Findings() {
  return (
    <div className="space-y-8">
      <SectionHeader
        eyebrow="Findings"
        title="All findings"
        subtitle="Every detected issue, grouped by severity and OWASP Agentic category."
      />
      <div className="flex flex-wrap gap-2">
        <Badge tone="high">High · 18</Badge>
        <Badge tone="medium">Medium · 64</Badge>
        <Badge tone="low">Low · 55</Badge>
      </div>
      <GlassCard interactive>
        <p className="text-sm text-slate-400">Select a finding to see evidence and remediation.</p>
      </GlassCard>
    </div>
  );
}

import { Button, GlassCard, SectionHeader } from "../components/ui";

export function Settings() {
  return (
    <div className="space-y-8">
      <SectionHeader
        eyebrow="Settings"
        title="Workspace settings"
        subtitle="Manage projects, integrations, and notification preferences."
      />
      <GlassCard>
        <div className="flex flex-wrap items-center justify-between gap-4">
          <div>
            <p className="text-sm font-medium text-white">Fail threshold</p>
            <p className="text-xs text-slate-500">Block merges at or above this severity.</p>
          </div>
          <div className="flex gap-2">
            <Button variant="ghost" size="sm">Low</Button>
            <Button variant="ghost" size="sm">Medium</Button>
            <Button variant="glow" size="sm">High</Button>
          </div>
        </div>
      </GlassCard>
    </div>
  );
}

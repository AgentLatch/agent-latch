import { Badge } from "../ui";
import { Sparkles } from "../ui/icons";

const ROADMAP = [
  "Runtime policy enforcement for live agents",
  "Tool-call monitoring and anomaly detection",
  "Guardrails that block unsafe actions in real time",
];

export function VisionCallout() {
  return (
    <section>
      <div className="relative overflow-hidden rounded-2xl border border-accent/20 bg-surface p-8 backdrop-blur-md sm:p-10">
        {/* Soft accent glow backdrop */}
        <div
          className="pointer-events-none absolute -right-20 -top-20 h-64 w-64 rounded-full bg-accent/20 blur-3xl"
          aria-hidden="true"
        />
        <div className="relative flex flex-col gap-5">
          <div className="flex items-center gap-3">
            <span className="grid h-10 w-10 place-items-center rounded-xl bg-accent text-white shadow-neon">
              <Sparkles className="h-5 w-5" />
            </span>
            <Badge tone="violet">Vision</Badge>
          </div>
          <h2 className="max-w-2xl text-2xl font-semibold text-white sm:text-3xl">
            Static today, runtime tomorrow
          </h2>
          <p className="max-w-2xl text-slate-400">
            AgentLatch is offline and static by design. The roadmap adds runtime protection layers that
            watch agents as they run — without giving up the local-first, zero-leakage principle.
          </p>
          <ul className="grid gap-2 sm:grid-cols-3">
            {ROADMAP.map((item) => (
              <li
                key={item}
                className="rounded-xl border border-white/10 bg-white/5 px-4 py-3 text-sm text-slate-300"
              >
                {item}
              </li>
            ))}
          </ul>
        </div>
      </div>
    </section>
  );
}

import { GlassCard, SectionHeader } from "../ui";
import { ExternalLink } from "../ui/icons";

const CATEGORIES = [
  { id: "ASI01", name: "Agent Goal Hijack" },
  { id: "ASI02", name: "Tool Misuse & Exploitation" },
  { id: "ASI03", name: "Identity & Privilege Abuse" },
  { id: "ASI04", name: "Agentic Supply Chain" },
  { id: "ASI05", name: "Unexpected Code Execution" },
  { id: "ASI06", name: "Memory & Context Poisoning" },
  { id: "ASI07", name: "Insecure Inter-Agent Comms" },
  { id: "ASI08", name: "Cascading Failures" },
  { id: "ASI09", name: "Human-Agent Trust Exploitation" },
  { id: "ASI10", name: "Rogue Agents" },
];

const OWASP_URL = "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/";

export function OwaspSection() {
  return (
    <section id="owasp" className="scroll-mt-24 space-y-8">
      <SectionHeader
        eyebrow="Research"
        title="Mapped to the OWASP Agentic Top 10"
        subtitle="Findings reference the OWASP Top 10 for Agentic Applications so teams can triage by a shared framework."
        action={
          <a
            href={OWASP_URL}
            target="_blank"
            rel="noreferrer"
            className="inline-flex items-center gap-2 rounded-xl border border-white/10 bg-white/5 px-4 py-2 text-sm font-medium text-slate-100 transition-all hover:border-white/20 hover:bg-white/10"
          >
            OWASP resource
            <ExternalLink className="h-4 w-4" />
          </a>
        }
      />
      <GlassCard>
        <ul className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
          {CATEGORIES.map((c) => (
            <li
              key={c.id}
              className="rounded-xl border border-white/10 bg-white/5 p-4 transition-colors hover:border-accent/30"
            >
              <p className="font-mono text-xs font-semibold text-accent-cyan-bright">{c.id}</p>
              <p className="mt-1 text-sm text-slate-300">{c.name}</p>
            </li>
          ))}
        </ul>
      </GlassCard>
    </section>
  );
}

import { Badge, Button } from "../ui";
import { ArrowRight, ExternalLink } from "../ui/icons";

const GITHUB_URL = "https://github.com/AgentLatch/agent-latch";

function scrollToResearch() {
  document.getElementById("owasp")?.scrollIntoView({ behavior: "smooth" });
}

export function Hero() {
  return (
    <section className="relative flex flex-col items-center gap-8 py-10 text-center sm:py-16">
      <Badge tone="violet" className="gap-2">
        <span className="h-1.5 w-1.5 rounded-full bg-accent" />
        Local-first · offline static analysis
      </Badge>

      <h1 className="max-w-4xl text-4xl font-bold leading-tight text-white sm:text-5xl md:text-6xl">
        Offline Static Security Scanner & Audit Tool for{" "}
        <span className="bg-gradient-to-r from-accent to-accent-cyan-bright bg-clip-text text-transparent">
          AI Agents
        </span>
      </h1>

      <p className="max-w-2xl text-lg leading-relaxed text-slate-400">
        Detect prompt injection vectors, excessive tool permissions, and compliance flaws across your
        Python code, agent manifests, and prompt templates — before deployment.
      </p>

      <div className="flex flex-col gap-3 sm:flex-row">
        <Button variant="glow" size="lg" onClick={scrollToResearch}>
          Explore OWASP Top 10 Security
          <ArrowRight className="h-4 w-4" />
        </Button>
        <a
          href={GITHUB_URL}
          target="_blank"
          rel="noreferrer"
          className="inline-flex h-12 items-center justify-center gap-2 rounded-xl border border-white/10 bg-white/5 px-6 text-base font-medium text-slate-100 transition-all hover:border-white/20 hover:bg-white/10 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/70 focus-visible:ring-offset-2 focus-visible:ring-offset-base"
        >
          View GitHub Repo
          <ExternalLink className="h-4 w-4" />
        </a>
      </div>
    </section>
  );
}

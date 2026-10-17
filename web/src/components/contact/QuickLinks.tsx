import type { ReactNode } from "react";
import { GlassCard } from "../ui";
import type { ToastKind } from "./toast";

const GITHUB_DISCUSSIONS = "https://github.com/AgentLatch/agent-latch/discussions";
const SECURITY_EMAIL = "security@agentlatch.io";

function GitHubIcon() {
  return (
    <svg viewBox="0 0 24 24" className="h-5 w-5" fill="currentColor" aria-hidden="true">
      <path d="M12 2a10 10 0 0 0-3.16 19.49c.5.09.68-.22.68-.48v-1.7c-2.78.6-3.37-1.34-3.37-1.34-.46-1.16-1.11-1.47-1.11-1.47-.9-.62.07-.6.07-.6 1 .07 1.53 1.03 1.53 1.03.89 1.52 2.34 1.08 2.91.83.09-.65.35-1.08.63-1.33-2.22-.25-4.56-1.11-4.56-4.94 0-1.09.39-1.98 1.03-2.68-.1-.26-.45-1.27.1-2.65 0 0 .84-.27 2.75 1.02a9.5 9.5 0 0 1 5 0c1.91-1.29 2.75-1.02 2.75-1.02.55 1.38.2 2.39.1 2.65.64.7 1.03 1.59 1.03 2.68 0 3.84-2.34 4.68-4.57 4.93.36.31.68.92.68 1.85v2.74c0 .27.18.58.69.48A10 10 0 0 0 12 2Z" />
    </svg>
  );
}

function MailIcon() {
  return (
    <svg viewBox="0 0 24 24" className="h-5 w-5" fill="none" stroke="currentColor" aria-hidden="true">
      <rect x="3" y="5" width="18" height="14" rx="2" strokeWidth="1.8" />
      <path d="m3 7 9 6 9-6" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function DiscordIcon() {
  return (
    <svg viewBox="0 0 24 24" className="h-5 w-5" fill="currentColor" aria-hidden="true">
      <path d="M19.3 5.3A17 17 0 0 0 15 4l-.2.4a12.8 12.8 0 0 1 3.7 1.2 14.4 14.4 0 0 0-12.9 0A12.8 12.8 0 0 1 9.3 4.4L9 4a17 17 0 0 0-4.3 1.3C2 9.4 1.4 13.4 1.7 17.3A17.2 17.2 0 0 0 7 20l.6-.8A11 11 0 0 1 5 17.9l.5-.3a12.3 12.3 0 0 0 13 0l.5.3a11 11 0 0 1-2.6 1.3l.6.8a17.2 17.2 0 0 0 5.2-2.7c.4-4.5-.6-8.5-2.9-12ZM8.5 14.8c-1 0-1.9-.9-1.9-2.1 0-1.1.8-2 1.9-2s1.9 1 1.9 2-.8 2.1-1.9 2.1Zm7 0c-1 0-1.9-.9-1.9-2.1 0-1.1.8-2 1.9-2s1.9 1 1.9 2-.8 2.1-1.9 2.1Z" />
    </svg>
  );
}

interface ChannelProps {
  icon: ReactNode;
  title: string;
  description: string;
  action: ReactNode;
}

function Channel({ icon, title, description, action }: ChannelProps) {
  return (
    <GlassCard interactive className="flex items-start gap-4">
      <span className="grid h-11 w-11 shrink-0 place-items-center rounded-xl bg-accent/15 text-accent-cyan-bright">
        {icon}
      </span>
      <div className="min-w-0 flex-1">
        <p className="text-sm font-semibold text-white">{title}</p>
        <p className="mt-1 text-xs text-slate-400">{description}</p>
        <div className="mt-3">{action}</div>
      </div>
    </GlassCard>
  );
}

const linkClass =
  "inline-flex items-center gap-1.5 text-sm font-medium text-accent-cyan-bright transition-colors hover:text-accent-cyan";

interface QuickLinksProps {
  /** Raise a toaster when a channel has no live destination yet. */
  onNotify: (kind: ToastKind, title: string, message?: string) => void;
}

export function QuickLinks({ onNotify }: QuickLinksProps) {
  return (
    <div className="grid gap-4">
      <Channel
        icon={<GitHubIcon />}
        title="GitHub Discussions"
        description="Ask questions, propose rules, or start an open-source contribution thread."
        action={
          <a href={GITHUB_DISCUSSIONS} target="_blank" rel="noreferrer" className={linkClass}>
            Open discussions →
          </a>
        }
      />
      <Channel
        icon={<MailIcon />}
        title="Security advisory"
        description="Report a vulnerability in AgentLatch privately, following our disclosure policy."
        action={
          <a href={`mailto:${SECURITY_EMAIL}`} className={linkClass}>
            {SECURITY_EMAIL}
          </a>
        }
      />
      <Channel
        icon={<DiscordIcon />}
        title="Community channel"
        description="Join the conversation with other developers building secure AI agents."
        action={
          <button
            type="button"
            onClick={() =>
              onNotify(
                "success",
                "Community invite coming soon",
                "The Discord community isn't open yet — reach us on GitHub Discussions meanwhile.",
              )
            }
            className={linkClass}
          >
            Join Discord →
          </button>
        }
      />
    </div>
  );
}

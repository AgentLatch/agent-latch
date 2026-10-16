import { GlassCard } from "../ui";
import { Rules, Star, Tag } from "../ui/icons";
import { useCountUp } from "../../hooks/useCountUp";
import { useGitHubStats } from "../../hooks/useGitHubStats";

/** Number of static heuristic rules shipped by the scanner (see the repo's rule tables). */
const STATIC_RULE_COUNT = 17;

function StatValue({ value, ready, suffix = "" }: { value: number; ready: boolean; suffix?: string }) {
  const display = useCountUp(value, ready);
  return (
    <span className="text-4xl font-bold text-white sm:text-5xl">
      {ready ? `${display.toLocaleString()}${suffix}` : "—"}
    </span>
  );
}

export function GitHubStats() {
  const { stars, releases, loading, error } = useGitHubStats();
  const haveStars = !loading && !error && stars != null;
  const haveReleases = !loading && !error && releases != null;

  return (
    <section>
      <GlassCard className="grid gap-6 sm:grid-cols-3">
        <div className="flex flex-col items-center gap-2 text-center">
          <Star className="h-6 w-6 text-accent" />
          <StatValue value={stars ?? 0} ready={haveStars} />
          <p className="text-sm text-slate-400">GitHub stars</p>
        </div>
        <div className="flex flex-col items-center gap-2 text-center sm:border-x sm:border-white/10">
          <Tag className="h-6 w-6 text-accent-cyan-bright" />
          <StatValue value={releases ?? 0} ready={haveReleases} />
          <p className="text-sm text-slate-400">Releases</p>
        </div>
        <div className="flex flex-col items-center gap-2 text-center">
          <Rules className="h-6 w-6 text-risk-low" />
          <StatValue value={STATIC_RULE_COUNT} ready suffix="+" />
          <p className="text-sm text-slate-400">Static heuristic rules</p>
        </div>
      </GlassCard>
      {error && (
        <p className="mt-3 text-center text-xs text-slate-500">
          Live GitHub stats are unavailable right now (API rate limit). Rule count is from the scanner.
        </p>
      )}
    </section>
  );
}

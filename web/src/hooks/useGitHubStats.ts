import { useEffect, useState } from "react";

export interface GitHubStats {
  stars: number | null;
  releases: number | null;
  loading: boolean;
  error: boolean;
}

const REPO = "AgentLatch/agent-latch";

/**
 * Fetch live GitHub stars and release count for the repo.
 * Uses the public GitHub REST API (no token). On failure (e.g. rate limit) the
 * values stay null so the UI can fall back gracefully.
 */
export function useGitHubStats(): GitHubStats {
  const [stats, setStats] = useState<GitHubStats>({
    stars: null,
    releases: null,
    loading: true,
    error: false,
  });

  useEffect(() => {
    let cancelled = false;
    const headers = { Accept: "application/vnd.github+json" };

    async function load() {
      try {
        const [repoRes, relRes] = await Promise.all([
          fetch(`https://api.github.com/repos/${REPO}`, { headers }),
          fetch(`https://api.github.com/repos/${REPO}/releases?per_page=100`, { headers }),
        ]);
        if (!repoRes.ok) throw new Error(String(repoRes.status));
        const repo = (await repoRes.json()) as { stargazers_count?: number };
        const releases = relRes.ok ? ((await relRes.json()) as unknown[]) : [];
        if (cancelled) return;
        setStats({
          stars: repo.stargazers_count ?? null,
          releases: Array.isArray(releases) ? releases.length : null,
          loading: false,
          error: false,
        });
      } catch {
        if (!cancelled) setStats({ stars: null, releases: null, loading: false, error: true });
      }
    }

    void load();
    return () => {
      cancelled = true;
    };
  }, []);

  return stats;
}

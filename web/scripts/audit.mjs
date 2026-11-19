import { spawnSync } from "node:child_process";
import {
  copyFileSync,
  existsSync,
  mkdtempSync,
  readFileSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const pinnedPicomatch =
  "https://codeload.github.com/micromatch/picomatch/tar.gz/7be3276fb8bd215a8c73fa066bcaf696c244ad88";
const scriptDir = dirname(fileURLToPath(import.meta.url));

function option(name, fallback) {
  const index = process.argv.indexOf(name);
  return index < 0 ? fallback : resolve(process.argv[index + 1]);
}

const manifestPath = option("--manifest", resolve(scriptDir, "../package.json"));
const lockPath = option("--lockfile", resolve(scriptDir, "../package-lock.json"));
if (existsSync(join(dirname(manifestPath), "npm-shrinkwrap.json"))) {
  console.error("npm-shrinkwrap.json is not supported; npm would audit it instead of package-lock.json.");
  process.exitCode = 1;
} else {
  const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
  const lock = JSON.parse(readFileSync(lockPath, "utf8"));
  const picomatchEntries = Object.entries(lock.packages ?? {})
    .filter(([name]) => name.endsWith("node_modules/picomatch"));

  if (manifest.overrides?.picomatch !== pinnedPicomatch
    || picomatchEntries.length === 0
    || picomatchEntries.some(([, entry]) => entry.resolved !== pinnedPicomatch)) {
    console.error("The picomatch manifest override and every lock entry must use the exact pinned tarball URL.");
    process.exitCode = 1;
  } else {
    const auditDir = mkdtempSync(join(tmpdir(), "agentlatch-npm-audit-"));
    try {
      copyFileSync(manifestPath, join(auditDir, "package.json"));
      copyFileSync(lockPath, join(auditDir, "package-lock.json"));
      const npmArgs = ["audit", "--audit-level=high", "--json"];
      const npmCli = process.env.npm_execpath;
      const result = npmCli
        ? spawnSync(process.execPath, [resolve(npmCli), ...npmArgs], {
          cwd: auditDir, encoding: "utf8", maxBuffer: 10 * 1024 * 1024,
        })
        : spawnSync("npm", npmArgs, {
          cwd: auditDir, encoding: "utf8", maxBuffer: 10 * 1024 * 1024,
        });
      if (result.error) throw result.error;
      if (result.status !== 0) {
        process.stderr.write(result.stdout || result.stderr);
        process.exitCode = result.status || 1;
      } else {
        const report = JSON.parse(result.stdout);
        const counts = report.metadata?.vulnerabilities;
        console.log(
          `npm audit: passed (${counts?.total ?? 0} advisory paths; none at high or critical).`,
        );
        process.exitCode = 0;
      }
    } finally {
      rmSync(auditDir, { recursive: true, force: true });
    }
  }
}

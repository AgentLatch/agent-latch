import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

const advisory = "https://github.com/advisories/GHSA-fc5q-39xc-vjpf";
const fixCommit = "7be3276fb8bd215a8c73fa066bcaf696c244ad88";
const lock = JSON.parse(readFileSync(new URL("../package-lock.json", import.meta.url), "utf8"));
const override = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"))
  .overrides?.picomatch;
const picomatchEntries = Object.entries(lock.packages)
  .filter(([name]) => name.endsWith("node_modules/picomatch"));

if (override !== `https://codeload.github.com/micromatch/picomatch/tar.gz/${fixCommit}`
  || picomatchEntries.length === 0
  || picomatchEntries.some(([, entry]) => !entry.resolved?.includes(fixCommit))) {
  console.error("The picomatch audit exception requires the pinned upstream fix commit in the manifest and lockfile.");
  process.exit(1);
}

const npmCli = process.env.npm_execpath;
if (!npmCli) {
  console.error("Run this audit through `npm run audit` so npm_execpath is available.");
  process.exit(1);
}

const result = spawnSync(process.execPath, [resolve(npmCli), "audit", "--audit-level=high", "--json"], {
  encoding: "utf8",
  maxBuffer: 10 * 1024 * 1024,
});
if (result.error) throw result.error;
if (result.status === 0) {
  const report = JSON.parse(result.stdout);
  const counts = report.metadata?.vulnerabilities;
  console.log(
    `npm audit: passed (${counts?.total ?? 0} advisory paths; none at high or critical).`,
  );
  process.exit(0);
}

let report;
try {
  report = JSON.parse(result.stdout);
} catch {
  process.stderr.write(result.stderr || result.stdout);
  process.exit(result.status || 1);
}
if (!report || !report.vulnerabilities || !report.metadata?.vulnerabilities) {
  process.stderr.write(result.stderr || result.stdout);
  process.exit(result.status || 1);
}

const vulnerabilities = report.vulnerabilities ?? {};
const allowed = new Set();
for (const [name, vulnerability] of Object.entries(vulnerabilities)) {
  if (name === "picomatch" && vulnerability.via?.length === 1
    && vulnerability.via[0]?.url === advisory) {
    allowed.add(name);
  }
}

// npm reports each transitive package as vulnerable; allow only dependency paths that lead
// exclusively to the patched picomatch advisory above.
let changed = true;
while (changed) {
  changed = false;
  for (const [name, vulnerability] of Object.entries(vulnerabilities)) {
    if (allowed.has(name) || !vulnerability.via?.length) continue;
    if (vulnerability.via.every((item) => typeof item === "string" && allowed.has(item))) {
      allowed.add(name);
      changed = true;
    }
  }
}

const rank = { low: 0, moderate: 1, high: 2, critical: 3 };
const blocking = Object.entries(vulnerabilities).filter(([name, vulnerability]) =>
  !allowed.has(name) && rank[vulnerability.severity] >= rank.high);

if (blocking.length) {
  process.stderr.write(result.stdout);
  process.exit(result.status || 1);
}

if (allowed.size) {
  const counts = report.metadata?.vulnerabilities;
  console.warn(
    `npm audit: passed; ${counts?.high ?? 0} high-severity advisory paths are limited to `
    + `${advisory}, with picomatch pinned to upstream fix ${fixCommit}.`,
  );
} else {
  console.log("npm audit: passed (no high or critical vulnerabilities).");
}

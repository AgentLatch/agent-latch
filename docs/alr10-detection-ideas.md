# ALR10 detection ideas (evaluation notes)

Ideas only. No code or pattern lists are copied from these projects. Licenses below are from
memory and **must be checked in each repository before anything is reused** (TruffleHog's is
the strictest of the three; use it for ideas and test inputs only). ALR10 stays local and
offline: no verification against a provider.

## Gaps against our masking patterns

Measured by `tests/test_alr10_heldout.py` (`KNOWN_MISSES`). Provider catalogues in
[Gitleaks](https://github.com/gitleaks/gitleaks), [TruffleHog](https://github.com/trufflesecurity/trufflehog)
and [detect-secrets](https://github.com/Yelp/detect-secrets), and the provider list in GitHub's
secret-scanning documentation, are the reference for what is missing:

| Gap | Shape to add (own regex, own tests) | Offline check available |
|---|---|---|
| GitLab personal access token | fixed prefix plus fixed-length body | prefix and length only |
| npm / package registry tokens | fixed prefix plus fixed-length body | prefix and length only |
| Stripe-style live keys | `live` / `test` marker prefix | prefix and length only |
| Google API key | fixed prefix plus fixed-length body | prefix and length only |
| Credentials inside a URL | `scheme://user:password@host` | structure |
| AWS secret access key in env lines | 40-character body next to an `AWS_SECRET…` name | context |
| Other AWS key-ID families (not only `AKIA`) | the documented 4-letter prefixes | prefix and length |
| Chat tokens beyond Slack, cloud keys beyond AWS | per provider docs | per provider |

## Offline false-positive control

- **Structure and checksums only.** GitHub tokens carry a checksum in their last characters, and
  AWS key IDs have a fixed prefix and length. Checking them offline rejects look-alikes such as
  `ghp_` followed by arbitrary text. This needs no network and keeps scans local.
- **Entropy plus context** (the detect-secrets idea): a token-shaped string is more likely real
  when it is high-entropy and sits next to a key-like name. Useful for the placeholder cases we
  still flag (`API_KEY=<your key>`): a value wrapped in `<...>` or `${...}` is a template, not a
  secret. Not implemented yet; the two known false positives are asserted in the held-out test.
- **Baseline of known false positives.** detect-secrets keeps a baseline file. Our equivalent is
  the operator policy (`--policy`), never a file from the monitored project.

## Not doing

- **Verification against the provider** (TruffleHog). It is network behavior: scans stay local.
- **Cleaning secrets from existing logs.** Out of scope.

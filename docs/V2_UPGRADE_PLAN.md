# Carapace Protocol V2 Upgrade Plan

Created from the 2026-06-12 continuous improvement audit.

## Current verified state

- GitHub latest release is v0.5.0, published 2026-05-23.
- README badge and roadmap still present v0.4.0 as current.
- README links ARIA to `https://relayforge.tools/aria/v1`, which returns 404.
- GitHub reports repository disk usage around 1,190,849 KB.
- A full clone attempt during audit produced a 1.1 GB partial `.git` directory and was stopped after more than 10 minutes.
- `.github/workflows` includes `ci.yml` and `publish.yml`.

## Linear tracking

- Parent: REL-543
- Findings: REL-544, REL-545

## V2 scope

1. Update public README/version badges/roadmap to v0.5.0 truth.
2. Replace broken ARIA links with the canonical live registry/docs route.
3. Add docs-link validation to CI.
4. Audit repository weight and move bulky tracked artifacts to releases, LFS, or external storage where appropriate.
5. Document shallow/sparse clone guidance for contributors and auditors.

## Done means

- Public protocol docs match the latest release and live ARIA surface.
- The repo can be cloned and audited without unreasonable weight.
- Existing CI/publish workflows guard docs and package truth.
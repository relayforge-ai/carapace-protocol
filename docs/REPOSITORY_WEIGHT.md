# Repository Weight

Carapace Protocol should stay lightweight enough for standards review,
security scanning, and first-time contributor onboarding. Do not use a normal
full clone when auditing historical repository weight; it can download large
historical blobs that are not present on `main`.

## Current State

Checked on 2026-06-14:

- GitHub reported repository disk usage: about 1,190,853 KB.
- The current `main` tree contains 92 files totaling about 942 KB.
- A metadata-only scan of 305 reachable commits / 286 unique trees found about
  1.26 GB of unique historical blob bytes.
- After deleting stale merged side-branch refs, the active remote-ref scan
  contained 40 commits / 28 unique trees / about 1.34 MB of unique blob bytes.

The current default branch is small. The repository weight comes from historical
objects reachable from side branches and tags, not from the present `main`
working tree.

## Known Large Historical Sources

The largest reachable historical objects are generated presentation and image
artifacts under paths such as:

- `cci-pptx/`
- `cci-slides/`
- `cci-slides-img/`
- `pptx_images/`

The largest single historical commit observed in the scan was
`aed9e24ef1fdff749703bf1e75d8524748f716d5`, reachable from
`origin/sheldon/dawes-public-publish` at the time of inspection. A smaller
historical source was committed framework build output under
`wizard/.next/cache/` in commit `9c5547024d14338b9d5d28cb97b8ad4871aebb25`.

On 2026-06-14, the stale `sheldon/dawes-public-publish` remote branch was
deleted after confirming it was not protected, was not the default branch, had
no open pull request, and was the only live ref keeping those large generated
artifacts reachable. Other merged stale side branches were also deleted, leaving
`main` and active work branches as the only remote heads.

## Audit-Friendly Clone

Use a blobless sparse clone for audits, docs work, and lightweight protocol
review:

```bash
git clone --filter=blob:none --sparse https://github.com/relayforge-ai/carapace-protocol.git
cd carapace-protocol
git sparse-checkout set README.md docs carapace python typescript tests
```

To inspect commit and tree history without downloading historical blobs:

```bash
git fetch --filter=blob:none --tags origin '+refs/heads/*:refs/remotes/origin/*'
git rev-list --all --count
```

Avoid commands that force blob materialization, such as opening historical
binary files or running size checks that call `git cat-file` on every blob.

## Cleanup Plan

1. Confirm whether the side branch containing generated presentation assets is
   still needed.
2. Move any asset bundles that must remain public to GitHub Releases, Git LFS,
   or external artifact storage.
3. Remove stale refs that keep bulky generated artifacts reachable.
4. If a history rewrite is required, coordinate it as a breaking maintenance
   event and notify downstream consumers before force-pushing.
5. Re-check `gh repo view relayforge-ai/carapace-protocol --json diskUsage`
   after GitHub has had time to prune unreachable objects.

## Guardrails

Generated decks, slide images, and build caches do not belong in this protocol
repository. `.gitignore` blocks the known bulky paths and framework cache
directories so new commits do not reintroduce the same problem.

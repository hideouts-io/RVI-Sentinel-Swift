# Repository instructions

## Git and GitHub

- Verify the canonical checkout, applicable overrides, branch, origin, revision, index, and dirty files before Git changes. Preserve unrelated work; isolate conflicting work in a worktree.
- Use a focused codex/ branch for a reviewable change. Keep uncommitted work available for user review unless a commit is authorized.
- Commit, push, PR creation, merge, tag, release, deployment, visibility changes, and deletion require authorization covering the operation and target. Honor an existing scoped authorization; do not infer publication from implementation approval.
- Stage explicit paths or approved hunks, review the complete staged diff, and keep private evidence and secrets out of GitHub.
- Merge only after applicable checks and conversations are satisfied for the latest candidate revision. Preserve required checks and prefer merge commits over rebase or squash when compatible with repository rules.
- Pin external Actions to upstream-verified full commit SHAs. Keep PR jobs read-only except the scoped code-scanning upload permission; publishing jobs require the protected github-release environment.

## Repository workflow

- Match the build/test command in .github/workflows/native-macos.yml: xcodebuild -project RVISentinel.xcodeproj -scheme RVISentinel -configuration Debug -derivedDataPath DerivedData CODE_SIGNING_ALLOWED=NO build test.
- Emit native CI on every PR to main; do not add workflow-level path filters to a required check.
- Follow README.md for opt-in physical-workflow tests. Ordinary CI does not verify live capture, privileged operations, or a physical device.
- Keep capture evidence private and state remaining runtime validation gaps in review and release claims.

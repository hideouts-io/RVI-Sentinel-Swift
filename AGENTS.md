# Repository workflow

- Match the build/test command in .github/workflows/native-macos.yml: xcodebuild -project RVISentinel.xcodeproj -scheme RVISentinel -configuration Debug -derivedDataPath DerivedData CODE_SIGNING_ALLOWED=NO build test.
- Emit native CI on every PR to main; do not add workflow-level path filters to a required check.
- Follow README.md for opt-in physical-workflow tests. Ordinary CI does not verify live capture, privileged operations, or a physical device.
- Keep capture evidence private and state remaining runtime validation gaps in review and release claims.
- Preserve Swift and Actions scanning in .github/workflows/codeql.yml. Require successful read-only analysis, separate upload jobs, and Code scanning uploads for the candidate revision.
- Source extraction and analysis use read-only tokens with upload: never and upload-database: false. Separate upload-only jobs publish SARIF; Code scanning uploads must succeed for every configured language.

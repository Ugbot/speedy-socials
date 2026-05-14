---
name: release
description: bump version, update changelog, tag and push a release
---

release the current changes. context (if any): $ARGUMENTS

## version locations
- `build.zig.zon` line 3: `.version = "x.y.z"`
- `src/relay/main.zig`: grep for `version=` in metrics endpoint
- `CHANGELOG.md`: add new section at top

## steps

1. **diff**: `git diff main --stat` + `git log main..HEAD --oneline` to understand what's shipping
2. **decide bump**: patch (fixes/small), minor (new features/APIs), major (breaking changes)
3. **update versions**: edit `build.zig.zon` and `src/relay/main.zig`
4. **changelog**: add `## x.y.z` section at top of CHANGELOG.md
   - one line per change, prefixed with `**feat**:`, `**fix**:`, `**refactor**:`, `**docs**:`
   - match existing style (terse, technical, no fluff)
5. **devlog**: if the work is substantial (new subsystem, major perf win, interesting technical story), suggest a devlog entry — ask before writing one
6. **verify**: `zig fmt --check . && zig build test`
7. **commit**: stage changed files, commit as `release: vx.y.z`
8. **tag + push**: `git tag vx.y.z && git push origin main --tags`

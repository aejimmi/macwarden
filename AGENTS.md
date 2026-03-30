# macwarden



Read AGENTS-CONTEXT.md for project-specific crates, domains, architecture, and custom rules.

## Team

- architect — researches domain, designs architecture, produces SPEC.md. Skills: macwarden:self-critique
- developer — implements from SPEC.md, fixes, tests alongside code. Skills: macwarden:test, macwarden:benchmark
- qa — coverage gaps, acceptance tests from SPEC.md criteria. Skills: macwarden:test, macwarden:coverage
- security — deep audits, dependency scanning, SPEC.md threat model verification. Skills: macwarden:security-audit, macwarden:dependency-update

Skills: macwarden:changelog, macwarden:features, macwarden:release, macwarden:readme, macwarden:web-changelog, macwarden:self-critique

## Workflow

### New work (project, feature, module)

Delegate to the architect agent before writing code for non-trivial work. The architect:
1. Researches the domain
2. Updates AGENTS-CONTEXT.md with architecture decisions
3. Creates focused specs in .claude/specs/ — one per feature or module

### Implementation

Follow the build order in AGENTS-CONTEXT.md. For each spec in .claude/specs/:
1. Delegate to developer agent with that spec's requirements
2. Delegate to qa agent for acceptance tests from the spec's criteria
3. After security-sensitive specs — delegate to security agent

### Shipping

Before the first release and each subsequent release:
1. `/macwarden:features` — populate FEATURES.md from current code
2. `/macwarden:changelog` — generate changelog from staged/committed changes
3. `/macwarden:readme` — write or update README.md
4. `/macwarden:doc-check` — validate documentation completeness
5. `/macwarden:release` — full gate: version bump, all checks, stops before commit

Shipping skills stage changes but NEVER commit. The user reviews and commits manually. The architect should include a shipping phase in the build order for new projects.

### Completion

Completion is enforced by hooks — cargo test must pass before the session ends. Acceptance tests written by qa from spec criteria are the definition of done.

## Priorities

Correctness > Performance > Ergonomics. When in conflict, this is the order.

## Codebase

- crates/ — domain-organized workspace crates.
- cargo clippy --all -- -D warnings must pass with no warnings.
- cargo fmt --all -- --check must pass.
- /// doc comments on all public items.

## Structure

- 500 lines max per file. Split if larger.
- Functions under 30 lines. Extract helpers if longer.
- Early returns over deep nesting.
- Tests in *_test.rs files, never inline #[cfg(test)].
  - Declare: #[cfg(test)] mod foo_test; in parent module.
  - Start with use super::*;
  - Name: test_<what>_<scenario>.
  - Use tempfile::TempDir for filesystem fixtures.
  - Test both success and error paths.

## Error Handling

- No .unwrap() in library code. Use ? or explicit handling.
- No expect() without descriptive message.
- Never discard errors with let _ = on fallible operations.
- Always add context: .context("failed to read header")?
- Use .get(i) over vec[i] when bounds aren't guaranteed.
- #[must_use] on important return types.
- catch_unwind at Rayon thread boundaries.
- thiserror for library errors, anyhow for binaries only.

## Performance

- Zero-copy by default: &str over String, &[T] over Vec<T>, Arc<T> for shared data.
- Cow<str> when ownership is conditional.
- Iterator chains over collecting into intermediate Vecs.
- No allocations in hot paths — pre-allocate, reuse buffers, use arena patterns.
- impl Trait over Box<dyn Trait> for singular return types.

## Concurrency

Preference order:
1. Channels (crossfire) — message passing over shared state
2. Atomics — counters, flags, progress
3. Locks — last resort, never in hot paths

Rayon for CPU-bound parallelism, Tokio for IO-bound async.

- Never block_on inside async context.
- spawn_blocking for CPU work from async — any rayon call from a Tokio task goes through tokio::task::spawn_blocking.
- No Tokio primitives from rayon threads — no .await, no Handle::current().
- tokio::sync::Mutex/RwLock in async code. std::sync::Mutex/RwLock in sync code. Never cross.
- LazyLock/OnceLock over lazy_static! or once_cell.
- Long-running tasks accept CancellationToken. Check cancellation via tokio::select!.

## Logging

Use tracing, not log. Controlled via RUST_LOG.

- error! — operation failed
- warn! — unexpected but recovered
- info! — lifecycle milestones
- debug! — internal flow

Structured fields over format strings: info!(path = %p, count, "done").

## Coverage

```bash
cargo llvm-cov --all --ignore-filename-regex '_test\.rs$'
```

# XDCC Core Project Memory

Current project state for contributors and agents. Keep this short and update it at each milestone.

**Last updated:** 2026-10-31

## Current state

- **Phase:** 0, research and design package delivered, and revised after independent review of nine findings in three rounds, plus one clarification. **Phase 0 is not closed.** It awaits owner review, and unresolved questions remain in `COMPATIBILITY.md` §5.
- **Implementation:** M0 is merged through PR #1, with its GitHub Actions checks passing. M1, the pure codecs in `src/proto/`, is implemented on `codex/m1-protocol-codecs`, plus tests and three fuzz targets. No network, storage, runtime, or transfer logic exists. `docs/research/` remains research only.
- **Gate:** authorization covers M0 and M1. Do not begin M2 or later milestones, E1, or publication without further authorization.
- **Repository:** M1 is uncommitted, for independent review. Hosted CI has not run on it, so M1's definition of done is still open. See `M1_REPORT.md`.
- **Local machine:** Rust 1.88.0, rustfmt, Clippy, and a nightly for fuzzing installed for verification with `CARGO_HOME=/tmp/xdcc-m0-cargo` and `RUSTUP_HOME=/tmp/xdcc-m0-rustup`, and cargo-fuzz under `/tmp/xdcc-m1-tools`. No shell files were modified; these paths are temporary and may be removed by the operating system.
- **Security contact:** D8 resolved by owner on 2026-10-31: `sec.krd.hub@proton.me`, documented in root `SECURITY.md`.
- **Missing inputs:** the brief refers to "Project Instructions" and "Project Context". Neither was in the repository or supplied. If they exist, reconcile this package with them.

## Project rules from the brief

- Do not assume undocumented XDCC behaviour is universal.
- Separate documented behaviour, conventions, and implementation-specific extensions.
- Legacy implementations are behavioural references, never code dependencies.
- Do not claim real-world compatibility until interoperability testing has occurred.
- Keep workspace complexity low.
- Milestones are small and independently reviewable.
- Do not claim universal compatibility from vendor documentation or simulated results.
- The ACK default above `u32::MAX` stays provisional until E1 and D9.

## Document map

| Topic | File |
|---|---|
| Wire behaviour, evidence, references | `PROTOCOL_SPEC.md` |
| Failure risks, matrix, open questions | `COMPATIBILITY.md` |
| Threat model, defaults | `SECURITY.md` |
| Modules, concurrency, state machines, API | `ARCHITECTURE.md` |
| Milestones, tests, acceptance | `DEVELOPMENT_PLAN.md` |
| Rust and Tokio decision | `adr/0001-language-and-runtime.md` |
| Pinned evidence, models, reproduction steps | `research/README.md` |
| M0 bootstrap scope, validation, outstanding work | `M0_REPORT.md` |
| M1 codec scope, corrections, validation, fuzz counts | `M1_REPORT.md` |

## Key findings

1. **No authoritative specification exists** for XDCC, RESUME, or >4 GiB ACKs. The best sources are mIRC's own docs and changelog, and source code.
2. **ACK width above 4 GiB:** mIRC 6.33 defined 8-byte ACKs when size exceeds 32 bits. Most open-source clients still send 4 bytes. iroffer-dinoex guesses from the first ACK.
3. **The iroffer guess can misfire:** a 4-byte client resuming past 4 GiB, or any 4-byte client that sends an ACK before data on a >4 GiB file, is treated as 8-byte. The heuristic is source-derived, and its misfires are modelled, not observed live. That this explains real-world connection resets is a separate, unverified hypothesis.
4. **Rule:** never ACK before data arrives.
5. **Completion must be local.** Notices, EOF, and ACKs prove nothing.
6. **Keep `wire_name` and `safe_name` separate,** since RESUME must echo what the bot sent.
7. **Offers can be retransmitted,** and transfers can depend on staying in a channel.
8. **Notices are translated and customisable,** so they are hints only.
9. **Path traversal in DCC remains a live bug class,** including a 2026 CVE in a Rust client.
10. **Offer parsing is deterministic.** The shape is chosen first, then values are validated, with no fallback.
11. **Reporting cannot block work.** The outcome cell is separate from events. Observers lag, transfers do not wait.
12. **`IrcLink` is a channel pair with epochs,** so reads and writes cannot block each other, and lines cannot cross reconnects.
13. **Overlap bytes are received but not written.** Use the `ARCHITECTURE.md` §7.6 counters, never a single received or written count.
14. **Atomic rename is not durability.** Use the ordered CP and F protocols. Process-crash tests do not prove power-loss durability.
15. **`Completed` is structural.** Content integrity exists only against a trusted digest. Same-length corruption under `SizeOnly` is undetectable by design.
16. **iroffer-dinoex is GPL-2.0-only,** which is incompatible with this repository's GPL-3.0. Models and simulators must be independent of its code.
17. **Aborting a task does not stop a filesystem operation.** Tokio documents this. One storage worker thread per transfer owns all file operations, and it cannot be aborted.
18. **A compare-and-swap gate decides cancellation.** After the worker claims it, only the worker commits. An outcome is never inferred from an aborted task.
19. **Shutdown never guesses.** If publication is unknown at the deadline, nothing is committed, and the transfer is reported as unresolved.
20. **Every checkpoint uses rule CE.** `D` never decreases, overlap cannot move it, and a failed sync poisons further checkpoints.
21. **A failed inspection is not evidence.** A publication probe returns `Same`, `Absent` or `Different`, or `Indeterminate`. Only `ENOENT` means absent. `Indeterminate` commits nothing and changes no file.
22. **An unknown publication always has one owner:** the worker, then the client's single reconciler, then startup recovery. Retries are bounded, and `wait()` stays pending meanwhile. This can happen after an operation returned an error, not only when one hangs.
23. **The job type sets permissions, not the thread.** On the reconciler thread, a probe job only inspects and commits. A recovery job may act, but only under the lock, on lookups made in that job, as §7.10 rows 1 to 3 direct.
24. **Truncation evidence must travel with the bytes.** `parse_ctcp` needs a `LineContext`, and tags never count toward the threshold. A cut ACCEPT is refused rather than read as a position mismatch.
25. **Fragments of oversized lines are never parsed,** since a cut line can look like a shorter valid one. The framer reports once, then discards through the next LF.
26. **`cargo deny` skips dev-dependencies' licences by default.** `include-dev = true` is required for it to review them. The fuzz package has its own lockfile and `deny.toml`, and needs its own run.
27. **A size limit must be checked before the work it limits.** Independent review of M1 found builders copying a body before refusing it. Allocation checks must include refused inputs and outbound paths, not only the parsers.
28. **`Vec::clone` does not keep spare capacity.** A fixed-buffer guarantee does not survive a derived `Clone`, so `LineFramer` is not `Clone`.

## Proposed decisions, pending approval

M0 authorization adopts D1 (retain the existing GPL v3 licence, recorded as
`GPL-3.0-only`), D2 (ADR 0001), D3 (one library and unpublished harness), and D11
(`xdcc-core` locally). D8 is resolved: the owner supplied `sec.krd.hub@proton.me`.
The registry returned HTTP 404 for
`xdcc-core` on 2026-10-31; this is a point-in-time observation, not a reservation.
Both crates have `publish = false`. Other decisions below remain proposals.

| ID | Decision | Recommendation | Why it needs the owner |
|---|---|---|---|
| D1 | Licence | Keep GPL-3.0 unless wider library adoption is a goal, in which case choose before any outside contribution. | GPL binds applications that link the library. Relicensing gets harder with each contributor. |
| D2 | Language and runtime | Accept ADR 0001 | Foundational |
| D3 | Crate structure | One published crate, plus unpublished `xdcc-sim` and `fuzz/` | Sets repository shape |
| D4 | IRC integration | Own byte-exact parser and small client, with the `IrcLink` channel pair as the embedding boundary. Do not depend on `irc`. | Adds code to own, in exchange for byte-exact behaviour. Hosts must run a small pump. |
| D5 | Public-network testing | Tier 1 self-hosted first. Tier 2 only with written rules. Does not cover E1, which is D13. | Legal, reputational, and network-policy exposure |
| D6 | mIRC testing | Buy or license a Windows test setup, or accept mIRC as vendor-doc-only | Cost |
| D7 | Passive source check | `WarnOnly` default | Trades passive interop for inbound safety |
| D8 | Security contact | **Resolved:** owner supplied `sec.krd.hub@proton.me` on 2026-10-31 | Recorded in root SECURITY.md |
| D9 | Default ACK width above 4 GiB | **Provisional:** 8 bytes, per mIRC's rule and the model. Decide from E1 evidence, before M9 closes and before the API freeze. | Unproven on live senders. No value is universally safe. |
| D10 | Default overlap on resume | 64 KiB verify | Slight re-download in exchange for detection |
| D11 | Crate name | Confirm `xdcc-core`, and check crates.io availability at M0 | Publishing is effectively permanent |
| D12 | Project scope | Receiver only for v0.1 | Excludes bot features |
| D13 | E1 authorisation | Approve a self-hosted, isolated ACK experiment with a research probe and generated data | Installs third-party software, needs test infrastructure, and adds a research tool |
| D14 | Research artifact licensing | Keep `docs/research/` in the repository as independent models. Have counsel review if D1 changes the licence or a release ships these files. | iroffer-dinoex is GPL-2.0-only. The models were written after reading its source. This is a risk call, not legal advice. |
| D15 | Durability claims | Linux-only power-loss claims, for L3-tested filesystems. Process-crash wording elsewhere. No physical power-cut testing. | Sets what users may be promised, and needs a privileged test runner |
| D16 | Parser strictness | Refuse legacy multi-word unquoted names, signed numbers, and nonzero-port-plus-token offers | Unknown interop cost until Q9 and Q18 have evidence |
| D17 | Storage worker threads | One dedicated OS thread per active transfer, with no `tokio::fs` for partials, plus one reconciler thread per client while it has reconciliation or recovery work | Adds a thread per transfer, and affects hosts with strict thread limits |
| D18 | Recovery after a failed finalisation | Allow recovery to publish a verified file whose intent reached disk, reported in `RecoveryReport`, even though the transfer committed `Failed` | The alternative holds the file for a host decision. Either is defensible. |
| D19 | Unresolved transfer semantics | Report unresolved transfers and commit nothing, accepting that `wait()` can stay pending while a kernel operation has not returned or publication cannot be established, and that an unresolved transfer keeps its slot | Changes what hosts must handle at shutdown and during storage outages |

## Next step

Independent review of M1, then hosted CI on all three operating systems. M2 and E1
remain unauthorized. See `M1_REPORT.md` and `DEVELOPMENT_PLAN.md` §2.

## Change log

| Date | Change |
|---|---|
| 2026-11-01 | Independent review of M1: outbound builders check length before allocating, `LineFramer` is no longer `Clone`, `BotNick` refuses all ASCII controls. Regression tests and fuzz coverage added. See `M1_REPORT.md`. |
| 2026-10-31 | Owner authorized M1. Codecs, vectors, property tests, allocation check, and fuzz targets added on `codex/m1-protocol-codecs`. CASEMAPPING confirmed from S2. API sketch and `PROTOCOL_SPEC.md` §3, §4, §7.5 refined. |
| 2026-10-31 | Owner supplied private security contact; D8 resolved and root SECURITY.md updated. |
| 2026-10-31 | Owner approved M0; workspace, empty crates, pinned toolchain, lints, dependency policy, CI and contributor/security documentation added. Local checks recorded in M0_REPORT.md; hosted CI and merge pending. |
| 2026-10-31 | Phase 0 package drafted |
| 2026-10-31 | Revised after independent review: parser, events, link, accounting, durability, acceptance criteria, E1 added, research artifacts added |
| 2026-10-31 | Second review: storage worker, publication gate and ledger, shutdown report, checkpoint rule CE, models extended |
| 2026-10-31 | Third review: three-valued publication probe, reconciler, `Held(PublicationUnknown)`, recovery rows 6 and 7, sidecar `file_id`, FA-1 and FA-2, probe model added |
| 2026-10-31 | Clarification: reconciler probe jobs and recovery jobs separated, INV-23, `ShutdownReport::recovery_busy`, recovery's actions after a repeated F2, job model added |

# XDCC Core Research Artifacts

Reproducible evidence behind the Phase 0 documents. Nothing here is production code. These scripts are not part of any crate, are not built, and are not shipped. They need only Python 3 and the standard library.

## Reproduce

From this directory:

```sh
python3 -I ack_behaviour_model.py
python3 -I offer_parser_check.py
python3 -I accounting_check.py
python3 -I durability_model.py
```

Each script exits non-zero if its results differ from the published documents.

| Script | Checks | Result on 2026-10-31 |
|---|---|---|
| `ack_behaviour_model.py` | `PROTOCOL_SPEC.md` §11.3 table | 11 of 11 cases match |
| `offer_parser_check.py` | `PROTOCOL_SPEC.md` §7.4 | 35 vectors, 200,000 round trips, 125,592 corrupted offers refused, 0 failures |
| `accounting_check.py` | `ARCHITECTURE.md` §7.6, rule CE in §7.9 | 10 scenarios, 4 eligibility points, 4,000 randomised multi-attempt runs, 121,332 checkpoints recorded, 176,928 skipped, 0 failures. The legacy rule would have decreased `D` 108,335 times, the revised rule 0 times. |
| `durability_model.py` | `ARCHITECTURE.md` §6 shutdown, probe, and reconciliation, §7.9, §7.10 | Published storage procedures unsafe, revised safe, as expected. Old shutdown design false at 6 of 9 points. Revised shutdown design: 3,795 interleavings, 0 violations. Earlier probe rules commit `Failed` with the file published in 4 of 11 cases. Revised probe design: 120,320 interleavings, 0 violations. Earlier recovery changes files on a failed lookup in 5 of 20 combinations, revised in 0. Probe and recovery truth tables: 16 lookup pairs each, 0 mismatches. Recovery jobs: 11,520 runs, 0 violations, and 70 orders against a new request, 0 violations. |

Results above came from Python 3.14.8 on CachyOS Linux. Other versions were not tried.

## What these do not prove

- None of them ran against a real bot, client, filesystem, or device.
- `ack_behaviour_model.py` models the sender behaviour described below. It does not show that a live iroffer-dinoex behaves this way. E1 tests that.
- `durability_model.py` proves ordering under its stated model only. Real filesystems may differ. **No filesystem evidence exists yet**, for any part of this project.
- The shutdown half of `durability_model.py` is an abstract interleaving model. It runs no filesystem call and no Tokio code. It assumes that a started operation cannot be interrupted by aborting a task, which comes from Tokio's documentation, and it was not measured here.
- The probe half of `durability_model.py` is also abstract. Its lookups return chosen values, so it says nothing about which errors real filesystems return, or when. It assumes FA-1 and FA-2 from `ARCHITECTURE.md` §7.10, except in two scenarios that break them on purpose, where the revised rule is expected to report a false `Failed`.
- `accounting_check.py` exercises the equations, not an implementation.
- `offer_parser_check.py` shows that the rules and vectors agree. It says nothing about what real senders emit. Its `is_zero` gained the 20-character number limit during M1, so that it matches `PROTOCOL_SPEC.md` §7.4. Its printed results did not change.

## How the models expose earlier contradictions

Each script keeps the superseded rule, so that the harness demonstrably detects the bug it was fixed for.

| Earlier contradiction | Exposed by | Result |
|---|---|---|
| CP1 set `T = A` for any caller, while AC-6 said `D` never decreases | `legacy_target` in `accounting_check.py`. The earlier script hid this with `max(D, ...)`, which has been removed. | Legacy rule decreases `D` before and partway through overlap |
| Failure path could checkpoint after a failed sync | Poison check in `accounting_check.py` | Revised rule records nothing |
| Shutdown committed `Cancelled` after publication | `old_at` in `durability_model.py` | False `Cancelled` at 6 of 9 steps, including an in-flight rename |
| A failed lookup after F2 was treated as a failed publication | `old_worker_rule` and `old_postmortem` in `durability_model.py` | False `Failed` in 4 of 11 cases, and 3 more correct only by luck |
| Recovery had no row for a failed lookup, so it read as absent | `startup_old` in `durability_model.py` | Changes files in 5 of 20 combinations |

The earlier shutdown model could not have found the last two. Its probe read the true file state, so a probe could never fail. It now uses the ledger rule, and the probe section sees only lookups.

Mutation check, run by hand on 2026-10-31. Each rule in the shutdown model and in rule CE was broken on purpose, in a temporary copy, to confirm the checks can fail.

| Mutant | Result |
|---|---|
| Remove `A <= D` guard | Caught |
| Remove poison guard | Caught |
| Finalize ignores `A == Z` | Caught |
| Worker ignores the gate | Caught |
| Deadline commits `Cancelled` on a claimed gate | Caught |
| Deadline treats in-flight as published | Caught |
| Probe assumes success | Caught |
| Post-publication failure reported as clean | Caught |
| Remove `V < Vt` guard alone | Survives. It is an equivalent mutant, since `A < E <= D` during overlap. The guard is kept as a defence (`ARCHITECTURE.md` §7.9). |

A second set covers the probe model. All 17 were caught.

| Group | Mutants |
|---|---|
| Worker | Commits `Failed` on `Indeterminate`. Assumes `Indeterminate` means published. Leaves no owner when handing off after the reconciler stopped. |
| Probe | Reads a failed `N` lookup as absent. Reads a failed `P` lookup as this file. Lets a failed `P` lookup block a confirmed `Same`. Counts both names gone as `Absent`. |
| Reconciler | Commits `Failed` on `Indeterminate`. Does not enforce the budget. Stacks attempts on re-arm. Starts a thread when a probe hangs. |
| Supervisor and shutdown | Deadline commits `Failed` for an unknown publication. Post-mortem ignores a `Published` ledger. Post-mortem probes when F2 never started. |
| Host and recovery | Discard allowed while unknown. Lock released at handoff, so a retry can republish. Recovery acts on a failed lookup. |

A third set covers reconciler jobs. All 22 were caught, and the 17 above were rerun against the final model. The first run caught 19. The three survivors exposed weak checks, not faults in the design, and those checks were then strengthened.

| Group | Mutants |
|---|---|
| Probe job | Publishes on `Absent`. Removes the partial name on `Same`. Applies a conflict policy. |
| Recovery job evidence | Reads a failed `N` lookup as absent. Reads a failed `P` lookup as this file. Ignores a busy lock. Looks before taking the lock. Acts without the lock. Row 5 removes the sidecar. A replaced `P` with `N` same goes to row 2. |
| Recovery job steps | Continues after stop. Continues on `Indeterminate`. Cleans up after a repeated F2 ends `Indeterminate`. Applies a conflict policy. |
| Scheduling | Retries itself. Host calls stack jobs. Spends a record's budget. Runs before ready probes. A hung job adds a thread. |
| Shutdown | Keeps the queue. Accepts jobs after stop. Forgets a running job. |

The shutdown model also has limits. It explores one transfer, one storage worker, and one shutdown. It treats each step as atomic, and it does not model the cancel token, job queue, or real timing.

The probe model has further limits. Interleavings allow two reconciler attempts and three scheduled lookup results, and the budget and hang checks are a separate small simulation. The world changes only through F2, so another process altering names while a transfer is unresolved is not modelled. It does not run reconciliation after a restart, the event stream, or `wait()`. These surfaces are requirements for OT-22 to OT-28, not modelled results.

The job model has further limits. A recovery job runs against a small state of two names and a sidecar, with no length or digest check, and a stop is modelled as a step count, not a concurrent signal. The lock check covers one recovery job against one new request, and takes the lock's exclusion as given. Real advisory lock behaviour is an M5 question. `recovery_report()`, `partials()`, and `ShutdownReport::recovery_busy` are represented only by a list in the scheduler check, so OT-29 to OT-31 remain requirements.

## Pinned sources

Read on 2026-10-31. Shallow clones, read only, nothing built.

| Project | Repository | Commit | Date | Licence |
|---|---|---|---|---|
| iroffer-dinoex | https://github.com/dinoex/iroffer-dinoex | `c4dbbeeeedcd53dadeb058255d0e85accdad7d82` | 2026-08-16 | GPL-2.0-only (SPDX tag in the source files read) |
| irssi | https://github.com/irssi/irssi | `43f1727ef9fe1cb51d5031ee2dd0e1965217e4cb` | 2026-01-27 | GPL family, not determined exactly |
| HexChat | https://github.com/hexchat/hexchat | `b544ac3350e85d4cc41fe3414cbdb82d75ce5d7a` | 2024-02-09 | GPL version 2 text in `COPYING` |
| WeeChat | https://github.com/weechat/weechat | `c07415da1b59ef413ec4d06576b493a0aced7e2e` | 2026-10-29 | GPL version 3 text in `COPYING` |
| KVIrc | https://github.com/kvirc/KVIrc | `d1de244fe7b45355237a871192d2680d9d9f1e86` | 2026-06-13 | GPL version 2 text in `COPYING` |
| xdccJS | https://github.com/JiPaix/xdccJS | `1dd78051e559f175b3918d5933c44ecbee3043b6` | 2025-01-27 | Not checked |
| xget | https://github.com/mario-campos/xget | `3c00207468b8cf2a7b4bc17d5b64b2734b329409` | 2023-02-25 | Not checked |

To re-read a source at its pinned commit:

```sh
git clone https://github.com/dinoex/iroffer-dinoex
git -C iroffer-dinoex checkout c4dbbeeeedcd53dadeb058255d0e85accdad7d82
```

`mIRC versions.txt` was fetched from https://www.mirc.com/versions.txt on 2026-10-31, SHA-256 `b11c196acf4069b3a954385d829b6651222a2406cbc14af585e423e6e4983ded`. The file changes with each release, so a later copy may differ.

## ACK behaviour model

### Behaviour modelled

Observed in iroffer-dinoex at the pinned commit:

| Location | Function | Behaviour |
|---|---|---|
| `src/dinoex_transfer.c:518` | `verify_acknowlede` | Width detection and rollover |
| `src/iroffer_transfer.c:503` | `t_readjunk` | Byte-wise ACK assembly |
| `src/iroffer_transfer.c:88` | `t_setup_send` | Applies configured `mirc_dcc64` |
| `src/iroffer_transfer.c:595` | `t_flushed` | Completion check in `WAITING` |
| `src/iroffer_transfer.c:792` | `t_setresume` | Sets the initial high-water mark |

The model implements this prose description, in its own structure:

- **B1.** A sender keeps a high-water mark, which starts at the resume position.
- **B2.** For a file above 32 bits, the first 4-byte value is examined once. If it is at or below the resume position, the sender switches to 8-byte framing and treats that value as the high half of the current frame. Its high-water mark momentarily becomes that value shifted left by 32 bits.
- **B3.** In 4-byte framing for a large file, a value below the high-water mark is raised by multiples of `2^32` until it is not.
- **B4.** In 8-byte framing, each frame is the high-water mark.
- **B5.** A configured sender starts in 8-byte framing for large files.

### Assumptions and limits

- ACK frames arrive whole and in order. TCP segmentation is not modelled, but framing is byte-based, so the result should not depend on it.
- Step size is 64 MiB. The result depends on the first value, not on the step.
- Only the bot's interpretation is modelled. Socket closure, kernel behaviour, RST, and timing are not.
- "Too early" means the high-water mark reached the file size before the receiver's true position did. By source reading, `t_flushed` only acts on that once the bot enters `WAITING`.
- The configured-mode flag is set in `t_setup_send` only on the branch that first opens the pack file (`file_fd == FD_UNUSED`). A concurrent second transfer of the same pack may not get it. The model assumes the flag applies. E1 should check this.
- Other iroffer versions, forks, and other bot software are not represented.

The source-derived heuristic, the modelled misclassification, and the reset hypothesis have different standing. See the table in `PROTOCOL_SPEC.md` §11.3.

## Licence note

iroffer-dinoex is GPL-2.0-only, and GPL-2.0-only code cannot be combined with GPL-3.0 code. This repository is GPL-3.0.

The first draft of the ACK model was a close transcription, held in a temporary directory. It was never added to this repository. `ack_behaviour_model.py` is a fresh model written from the B1 to B5 description, with its own structure and names, and copies no upstream code or comments. Its traces were compared with the earlier scratch model on 72 cases, with no differences, and that scratch model was not added to the repository.

Its author had read the upstream source, so this is not a formal clean-room process. The owner should treat that as a known risk (decision D14). This note is not legal advice. The same rule applies to the `iroffer-like` simulator profile.

## External references for the durability and concurrency design

| Topic | Source |
|---|---|
| `fsync` and directory entries | https://man7.org/linux/man-pages/man2/fsync.2.html |
| `RENAME_NOREPLACE` support and `EINVAL` | https://man7.org/linux/man-pages/man2/rename.2.html |
| Failed `fsync` and dropped pages | https://lwn.net/Articles/752063/ |
| `dm-log-writes` | https://www.kernel.org/doc/html/latest/admin-guide/device-mapper/log-writes.html |
| Windows file flush | https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-flushfilebuffers |
| Windows `MoveFileExW` | https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw |
| Rust `sync_all` on Unix | `library/std/src/sys/fs/unix.rs` in rust-lang/rust, master on 2026-10-31: `F_FULLFSYNC` on Apple targets |
| Rust `sync_all` on Windows | `library/std/src/sys/fs/windows.rs`, same date: `FlushFileBuffers` |
| Tokio channel cancel safety | https://docs.rs/tokio/latest/tokio/sync/mpsc/struct.Sender.html |
| Tokio broadcast lag | https://docs.rs/tokio/latest/tokio/sync/broadcast/index.html |
| `abort` and blocking tasks | https://docs.rs/tokio/latest/tokio/task/struct.JoinHandle.html |
| `spawn_blocking`, shutdown, dedicated threads | https://docs.rs/tokio/latest/tokio/task/fn.spawn_blocking.html |
| Runtime drop and `shutdown_timeout` | https://docs.rs/tokio/latest/tokio/runtime/struct.Runtime.html |
| `tokio::fs` cancellation | https://docs.rs/tokio/latest/tokio/fs/index.html |
| `tokio::fs::File` close behaviour | https://docs.rs/tokio/latest/tokio/fs/struct.File.html |
| Program exit and spawned threads | https://doc.rust-lang.org/std/thread/index.html |

## Adding artifacts

Keep each one small, with no dependencies. State what it proves and what it does not. Make it exit non-zero on disagreement. Do not copy code from reference projects.

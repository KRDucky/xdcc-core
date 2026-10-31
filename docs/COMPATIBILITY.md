# XDCC Core Compatibility

**Status:** Phase 0 draft, revised after independent review, 2026-10-31.

**XDCC Core has no real-world compatibility claims.** Nothing has been implemented or run against a live bot. Every entry below describes other software, as read from its source. Vendor documentation describes the vendor's product, and a simulated pass describes the simulator. Neither establishes compatibility. Evidence tags and reference IDs are defined in `PROTOCOL_SPEC.md`.

## 1. Protocol compatibility matrix

Key: ✓ supported in source, ✗ absent or not representable, ~ partial or conditional, ? not determined. **n/a** means not applicable to that role.

| Feature | iroffer-dinoex | mIRC | irssi | HexChat | WeeChat | KVIrc | xdccJS | xget | XDCC Core plan |
|---|---|---|---|---|---|---|---|---|---|
| Role reviewed | Sender | Vendor docs only | Both | Both | Both | Both | Receiver | Receiver | Receiver |
| `DCC SEND` | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | M6 |
| Size above 32 bits in offer | ✓ | ✓ 6.33+ | ✓ | ✓ | ✓ | ✓ | ✓ | ? | M9 |
| Quoted filename | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ? | M1 |
| Unquoted name with spaces | sends if configured | ? | ✓ tolerated | ✗ | ✗ | ? | ✗ | ? | M1, with size only |
| RESUME and ACCEPT | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✗ | M7 |
| Passive offer | ✓ configured | ✓ 6.17+ initiates | ✓ | ✓ | ✓ token parsed | ✓ | ✓ | ? | M8 |
| Passive resume | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ~ | ✗ | M8 |
| IPv6 address | ✓ | ~ | ✓ | ✗ | ? | ✓ | ~ passive alpha | ? | M8 |
| 4-byte ACK | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ~ optional | M6 |
| 8-byte ACK | ✓ auto or configured | ✓ size > 32 bits | ✗ | ✗ | ✗ | ~ off by default | ✓ size > 32 bits | ? | M9, provisional pending E1 |
| Sends ACK before data on resume | n/a | ? | no | no | ? | **yes** | no | n/a | **Forbidden** |
| Runs ahead of ACKs | ✓ | ✓ 6.33+ | ? | ✓ fast send | ✓ fast send | ✓ option | n/a | n/a | Tolerated |
| Stores partial as temp name | n/a | ? | ? | no | ✓ optional | ? | ? | no | ✓ M5 |
| Basename enforcement | n/a | ? | ✓ | ✓ | ✓ | ✓ | ? see report | ✓ rejects | ✓ M2 |
| TSEND | ✗ in code read | ? | ? | ? | ? | ✓ | ✗ | ✗ | Refuse, later |
| SSEND | ✗ in code read | ? | ? | ? | ? | ✓ | ✗ | ✗ | Refuse, later |

Unknown-heavy columns are not a reason to assume support. "mIRC" is vendor documentation only, since it is closed source.

### XDCC Core v0.1 target

| Capability | State |
|---|---|
| Simulated bot: standard, iroffer-like, mIRC-like | Target for M7 to M9 |
| Self-hosted ACK behaviour, exact tested versions only | E1, narrow experiment |
| Live iroffer-dinoex, self-hosted, full feature set | Target for M11 |
| Other bot software | Unknown until evidence exists |
| Public networks | Unknown until evidence exists |

## 2. Why XDCC transfers fail

Ranked by severity, then frequency as a reasonable judgment from the evidence. Failure frequency in the field has not been measured.

**Severity:** S1 silent corruption or wrongly reported success, or a security impact. S2 transfer fails, and data or time is lost. S3 transfer fails cleanly and is recoverable. **Complexity:** L, M, H.

| # | Risk | Sev | Cplx | Mitigation |
|---|---|---|---|---|
| R1 | Reporting success from a short file, typically EOF at end of stream, a notice, or an ACK. Size in the offer is untrusted, and `S4` says the receiver cannot know completion without it. | S1 | M | Local byte accounting with size required, and overrun detection. `ARCHITECTURE.md` §7.5. |
| R2 | Resume against different file content. Same name, new content, or a changed pack. DCC has no content identity. Overlap sees only the join, so a change elsewhere needs a trusted digest. | S1 | M | Sidecar identity, overlap verification, trusted digest |
| R3 | Resume from a tail that was not durable. After power loss a partial may be longer than its valid data. mIRC's 8192-byte chop exists for this reason [V2]. | S1 | M | Ordered checkpoint protocol, cut the untrusted tail at first new write |
| R4 | ACK width mismatch above 4 GiB. Modelled to cause bot-side premature close or a stall. iroffer cases in `PROTOCOL_SPEC.md` §11.3 [M]. Not yet observed live. | S2 | H | Provisional width rule, no initial ACK, profiles, resume on short close, E1 |
| R5 | Filename parsing or echo errors. Bad RESUME match, wrong name on disk, or a malformed offer reinterpreted as another shape. Includes spaces, quotes, non-UTF-8. | S2 | M | Deterministic parser with no fallback, `wire_name` and `safe_name` separation |
| R6 | Resume offset mismatch: ACCEPT carries another position, or position equals size and no ACCEPT arrives. | S2 | L | Exact match. Equal-size path. Timer. |
| R7 | Passive connection failure: wrong advertised address, closed port, NAT. Containers in bridge mode have a non-routable address. | S2 | M | Explicit `advertise_addr` and port range. No IP guessing. Clear errors. Active preferred. |
| R8 | IRC session lost or channel left during transfer. iroffer can close active transfers [I1]. | S2 | M | Keep session up. Rejoin. Classify as resumable. |
| R9 | Duplicate offer from reminder retransmission creating a second transfer. | S2 | L | Idempotent offer handling |
| R10 | Stall with no EOF. Half-open connections leave clients hanging. | S2 | L | Stall timer, resumable |
| R11 | Receiver blocked by ACK write, deadlocking when both sides have full buffers. | S2 | M | Independent ACK path, coalescing |
| R12 | Retries triggering bans, or queue loss from over-aggressive retry. | S2 | L | Per-bot budget, backoff, no retry on denial |
| R13 | Offer from a nick other than the one requested, as with relay bots. I6's `botNameMatch` option exists because of this. Rejecting breaks interop and accepting weakens correlation. | S2 | M | Reject by default. Scoped alias list only. |
| R14 | Inconsistent CTCP parsing: missing final `0x01`, embedded markers, lowercase tags. | S3 | L | `PROTOCOL_SPEC.md` §4 rules |
| R15 | Unknown or translated bot notice leading to a wrong state. | S3 | L | Notices are advisory |
| R16 | `You already requested that pack` after a failed attempt, since the bot's state outlives the client's. | S3 | L | `XDCC CANCEL` then delayed retry |
| R17 | Truncated long offer read as a size-less offer, or with a cut size field. | S3 | L | `SuspectedTruncation`, overrun check |
| R18 | Overlong RESUME that cannot fit in a line. | S3 | M | Explicit error. Q8. |
| R19 | Disk full, or a rename failure at the end. mIRC 7.65 fixed reporting completion without enough disk space [V2]. | S1 | L | Pre-flight space check, write-error propagation |
| R20 | Unexpected bot response ordering: offer before notice, or notice after. | S3 | L | State machine accepts either order |

### Priority order for implementation

R1, R2, R3, and R19 come first, since they break the core promise and are moderate work. R4 is the highest-complexity item, and it can only be fully closed with live evidence.

## 3. Bot compatibility profiles

A profile is data, not code paths. It sets only the values below.

| Setting | `standard` (default) | `iroffer-dinoex` | `mirc-like` | `strict` |
|---|---|---|---|---|
| Request form | `XDCC SEND #n` | same | same | same |
| ACK width above 32 bits, provisional (D9) | 8 | 8 | 8 | 8 |
| Overlap bytes | 64 KiB | 64 KiB | 64 KiB | 64 KiB |
| Accept nick aliases | off | off | off | off |
| Legacy offer without size | refuse | refuse | refuse | refuse |
| Dotted IPv4 | accept | accept | accept | refuse |
| Notice patterns | none | iroffer English | none | none |
| Passive | allow if configured | allow if configured | allow if configured | refuse |

Profiles must not relax `SECURITY.md` invariants. Only the host's `SecurityPolicy` can do that. The `iroffer-dinoex` and `mirc-like` names describe the behaviour a profile targets, not a tested result.

## 4. Simulated behaviour profiles

`xdcc-sim` models the following. Each is labelled by source so a simulated pass is not mistaken for live compatibility.

| Sim profile | Models | Source |
|---|---|---|
| `spec-1994` | Stop-and-wait, 4-byte ACKs | S3, S4 |
| `iroffer-like` | ACK detection per the behavioural model, `WAITING` close, 180 s timer, reminders, notices. Written independently, not derived from upstream code. | I1 |
| `mirc-like` | 8-byte above 32 bits, run-ahead, no-ACK tolerance | V2 |
| `hexchat-like` | Low-word accounting, fast send, `199` passive address | I3 |
| `irssi-like` | Low-word accounting | I2 |
| `hostile` | Everything in `DEVELOPMENT_PLAN.md` §3.3 | Threat model |

## 5. Unresolved compatibility questions

Phase 0 is **not** closed on these. None can be settled by reading alone. The "Stage" column gives the earliest point that can answer each one.

| ID | Priority | Question | How to resolve | Stage |
|---|---|---|---|---|
| Q1 | High | Do live bots behave correctly with 8-byte ACKs above 4 GiB, and do 4-byte-only senders tolerate them? | Self-hosted iroffer, and each client as sender, with 5 GiB files | E1, then M11 |
| Q2 | High | Is the RST hypothesis for last-bytes failures true? This is unverified, and separate from the source-derived heuristic finding. | Capture with `mirc_dcc64` set and a 4-byte client | E1 |
| Q3 | High | What bot software is deployed now, and at what share? | Owner decision on a passive CTCP VERSION survey, if permissible | M11 |
| Q4 | High | Which active-versus-passive ratio do real bots use? | Same survey, by offer shape only | M11 |
| Q5 | Medium | Do non-iroffer bots accept `#n`, lowercase, and CTCP request forms? | Interop | M11 |
| Q6 | Medium | Do relay bots send offers from a different nick? | Interop, and why `botNameMatch` was added upstream | M11 |
| Q7 | Medium | Is overlap resume accepted by all senders? It should be, since it is only a lower position. | Interop | M11 |
| Q8 | Medium | What should happen when the RESUME line cannot fit? Can name be shortened, relying on port match, as mIRC does? | Interop | M11 |
| Q9 | Medium | Do any senders emit negative or signed integers for address or size? | Corpus from captures | M11 |
| Q10 | Medium | Does any sender offer via NOTICE, or to a channel? | Interop | M11 |
| Q11 | Medium | Which encodings appear in filenames in practice? | Corpus | M11 |
| Q12 | Medium | How does mIRC's closed-source sender react to edge cases? | Owner decision: Windows test host | M11 |
| Q13 | Low | Is a zero token used in passive offers? | Corpus | M11 |
| Q14 | Low | Does turbo appear without announcement, per X3? | Corpus | M11 |
| Q15 | Low | Do bots require channel presence for the whole transfer by default? | Default for `restrictsend` in iroffer sample config is commented out, deployments are unknown | M11 |
| Q16 | Low | What is the exact behaviour of `file.ext` era senders? | Probably moot. Confirm no live use. | M11 |
| Q17 | Low | Does any live bot offer zero-length files, and does any sender wait for an ACK on one? | Corpus | M11 |
| Q18 | Low | Do any senders send a nonzero port with a token to a receiver? It is refused today. | Corpus | M11 |
| Q19 | Low | Is the 480-byte truncation threshold right for real relayed lines? | Corpus | E1, M11 |

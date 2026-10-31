# XDCC Core Security Model

**Status:** Phase 0 draft, revised after independent review, 2026-10-31. Design only. No control below exists yet.

## 1. Trust model

XDCC is unauthenticated peer traffic triggered by chat messages. A DCC offer tells a client to connect to an attacker-chosen address and write attacker-chosen bytes to an attacker-suggested filename. Treat every byte from IRC or DCC as hostile.

| Boundary | Trust |
|---|---|
| Host application, config | Trusted |
| Local filesystem | Trusted, except for concurrent local actors in shared directories |
| IRC server | Semi-trusted, relays attacker content |
| IRC users, including the bot | Untrusted. Nick is not identity. |
| DCC peer, DCC data | Untrusted, unauthenticated, normally plaintext |

**Assets:** user's files, user's internal network, IP address, disk and memory, integrity of downloads, the host's IRC connection.

**Out of scope:** malware in correctly transferred files. A byte-perfect download can still be malicious. The library should not execute, open, or mark content as safe.

## 2. Security invariants

These hold in every mode. Compatibility profiles cannot weaken them.

| ID | Invariant |
|---|---|
| SEC-1 | No TCP connection or listener exists for a transfer without an open local request that matches the offer. |
| SEC-2 | Every destination is checked by `NetPolicy` immediately before connect, on the parsed `IpAddr`. |
| SEC-3 | Hostnames in offers are never resolved. |
| SEC-4 | No path derived from the network is opened except through the capability directory, after sanitising. |
| SEC-5 | Existing files are never overwritten or followed through symlinks. |
| SEC-6 | Bytes written never exceed the offered size, and the offered size never exceeds policy. |
| SEC-7 | All buffers, queues, and timers are bounded. |
| SEC-8 | `Completed` is emitted only after `ARCHITECTURE.md` §7.5 passes. |
| SEC-9 | No CR, LF, NUL, or `0x01` from the network reaches an outbound line outside the CTCP delimiters. |
| SEC-10 | Unsafe code is forbidden in `xdcc-core`. Platform calls go through audited crates. |
| SEC-11 | A malformed offer is refused. It is never reinterpreted as a different shape. |
| SEC-12 | No security control depends on a host consuming events. |
| SEC-13 | `Discard` deletes only partial and sidecar files, and runs only after the publication gate closed. A published file is never deleted. While publication is unknown, nothing is deleted, cleaned up, or published again (`ARCHITECTURE.md` §6). A probe job changes no file. A recovery job changes files only under the partial's lock, on lookups made in that job, as §7.10 rows 1 to 3 direct. |

## 3. Threat model

Likelihood and impact are design estimates.

| ID | Threat | Likelihood | Impact | Mitigation |
|---|---|---|---|---|
| T1 | Unsolicited `DCC SEND` | High | High | SEC-1. Unmatched offers are dropped and counted. |
| T2 | Offer from impersonated nick, after the real bot quits | Medium | High | Nick match, short window, `user@host` pin at request time where known, hash where known |
| T3 | SSRF: offer points at a loopback or internal service | High | High | SEC-2, §4 |
| T4 | Path traversal in filename | High | Critical | SEC-4, §5. Recent real example: CVE-2026-32733 in a Rust client [X4]. |
| T5 | Overwrite by symlink or file swap | Medium | Critical | §6 |
| T6 | Disk exhaustion through huge claimed size | High | High | `max_file_size`, free-space check, no preallocation by default |
| T7 | Data overrun beyond the claimed size | Medium | Medium | SEC-6 |
| T8 | Slowloris: peer holds transfer open | Medium | Medium | Stall timer, optional minimum rate, concurrency cap |
| T9 | Offer flood | High | Medium | Bounded channel, per-nick rate limit, drop without allocation |
| T10 | Parser panic, memory blow-up, or field confusion | Medium | High | Bounded input, deterministic parser with no fallback (SEC-11), fuzzing, `forbid(unsafe_code)`, no recursion |
| T11 | Unsafe resume: appending to another file | Medium | High | Sidecar identity, overlap check, `0600`-style sidecar, held partials are never auto-resumed. Changes outside the overlap need a trusted digest. |
| T12 | Unexpected inbound connection on a passive port | Medium | Medium | §7 |
| T13 | Tampering or eavesdropping on plaintext DCC | Medium | High | Warning. Trusted digest where available. `SizeOnly` is reported as such. No false claim of integrity. |
| T14 | Local attacker in a shared download directory | Low | High | Owner-private directory check, `O_NOFOLLOW` equivalents, exclusive create |
| T15 | Terminal or log injection through filenames and notices | Medium | Medium | Control bytes neutralised in `Display`. Raw bytes only through explicit accessors. |
| T16 | IRC line injection through a host-supplied or echoed value | Medium | High | SEC-9, validated newtypes |
| T17 | NAT helper abuse: `nf_conntrack_irc` opens ports from crafted messages [X5] | Medium | Medium | TLS to IRC by default, never reflect `0x01` |
| T18 | IP disclosure | High | Low | Passive off by default. Documented. Every connection reveals the IP to the peer. |
| T19 | Ban or abuse report from aggressive retry | Medium | Medium | Per-bot retry budget |
| T20 | Dangerous filenames for consumers: bidi overrides, reserved Windows names, leading dashes | High | Medium | §5 |
| T21 | Malicious resume ACCEPT from a third party | Medium | Medium | Exact match of nick, port or token, and position |
| T22 | Dependency compromise | Low | High | `cargo-deny`, `cargo-audit`, pinned lockfile for CI, minimal dependency set |

## 4. Network destination policy

Default **deny** for destinations in these ranges. Decisions run on canonicalised addresses, so IPv4-mapped IPv6 such as `::ffff:127.0.0.1` is evaluated as IPv4.

| Range | Reason |
|---|---|
| `0.0.0.0/8`, `::/128` | Unspecified. Port 0 in a non-passive offer is also invalid. |
| `127.0.0.0/8`, `::1/128` | Loopback |
| `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7` | Private |
| `100.64.0.0/10` | CGNAT |
| `169.254.0.0/16`, `fe80::/10` | Link-local, including cloud metadata at `169.254.169.254` |
| `192.0.0.0/24`, `192.0.2.0/24`, `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32` | Special-use, benchmark, documentation |
| `224.0.0.0/4`, `240.0.0.0/4`, `ff00::/8` | Multicast, reserved, broadcast |
| `64:ff9b::/96`, `64:ff9b:1::/48` | NAT64, embedded IPv4 is re-evaluated |
| `2002::/16` | 6to4, embedded IPv4 is re-evaluated |

**Ports.** Reject ports below 1024 by default. Whether any live bot listens below 1024 is unverified (`COMPATIBILITY.md` Q3). HexChat carries a similar check, commented out, which suggests it once caused a problem. Tests and LAN use set `allow_private_destinations` explicitly.

```rust
pub struct NetPolicy {
    pub allow_private_destinations: bool,   // default false
    pub allow_low_ports: bool,              // default false
    pub deny: Vec<IpNet>,                   // always wins
    pub allow: Vec<IpNet>,                  // overrides the built-in deny list
    pub passive: PassivePolicy,             // default Disabled
}
```

**Why SSRF severity stands even with no attacker-chosen request body.** A DCC receiver writes ACK bytes to the destination and stores what it returns. This allows port scanning through timing, sending short binary junk to internal services, and storing a banner in a file.

## 5. Filename sanitising

Output is a single path component, or a refusal. The input is treated as bytes.

1. Decode UTF-8. Invalid bytes map to replacement via lossy decoding. `wire_name` keeps the original.
2. Take the part after the last `/` or `\`.
3. Remove control characters, bidi controls (U+202A to U+202E, U+2066 to U+2069), and zero-width and BOM characters.
4. Replace `< > : " | ? *` with `_`. Colon also blocks NTFS alternate data streams.
5. Strip leading dots, leading spaces and leading dashes. Strip trailing dots and spaces.
6. Reject empty results, and `.` or `..`.
7. Prefix Windows reserved stems (`CON`, `PRN`, `AUX`, `NUL`, `COM0`–`COM9`, `LPT0`–`LPT9`), on every platform for portable results.
8. Reject names ending in the reserved `.xdccpart` or `.xdccmeta` suffixes.
9. Truncate to 200 UTF-8 bytes on a character boundary, preserving the extension.
10. Apply NFC normalisation for stable comparison.

Percent sequences are not decoded, so `%2F` stays literal and cannot become a separator. KVIrc treats it as a separator. Decoding is the behaviour that creates risk, and leaving it as text is safe.

Rejecting is preferred to guessing. Hosts can supply `name_override`.

## 6. Filesystem operations

The download directory is opened once as a capability (`cap_std::fs::Dir`). `Dir::open_ambient_dir` is the only ambient-authority call, and it is confined to the storage constructor.

| Step | Operation |
|---|---|
| Open partial, new | `create_new(true)` with mode `0600` under the capability root |
| Open partial, existing | No-follow open, verify regular file, single hard link, owned by the current user. The one exception to the link count is recovery row 3 in `ARCHITECTURE.md` §7.10. |
| Lock | Advisory lock on the partial to prevent two transfers |
| Durable checkpoint | Rule CE, then ordered protocol CP1 to CP7 in `ARCHITECTURE.md` §7.9: sync partial, write and sync temp sidecar, rename, sync directory. `D` never decreases. |
| Finalize | Ordered protocol F0 to F6 in `ARCHITECTURE.md` §7.10: sync file, claim the gate, record intent, no-replace publish, sync directory, clean up. One uninterruptible job on the storage worker. |
| Recovery | Startup recovery in `ARCHITECTURE.md` §7.9 and §7.10. Held partials need a host decision. |

**Final rename.** Linux uses `renameat2` with `RENAME_NOREPLACE`, through `rustix::fs::renameat_with`. Other platforms, and Linux filesystems returning `EINVAL`, use `Dir::hard_link` followed by `remove_file`, which also fails if the target exists. A crash between those two calls leaves two names for one file, which recovery resolves. Filesystems without hard links fail with an explicit error rather than a racy check. M5 confirms this per platform.

**Durability limits.** Durability means "subject to the platform honouring its sync calls". `ARCHITECTURE.md` §7.10 lists what is claimed per platform. In summary, Windows has no documented directory flush, macOS and Windows are process-crash tested only, network and FUSE filesystems carry no power-loss claim, and a device that ignores flushes cannot be detected. A sync failure ends the attempt and is never retried on the same data.

**Conflict policy.** An existing final name produces `FinalExists`. `Rename` picks `name (1).ext` through the same no-replace path. `Overwrite` does not exist.

**Permissions.** Files finish as `0640` on Unix, or the host's configured mode. Execute bits are never set.

## 7. Inbound connections

Passive is **off by default**. When enabled:

- Binding uses a host-configured address and port range.
- One listener serves one transfer, accepts exactly one connection, then closes.
- The listener lifetime is short, default 60 seconds.
- Source IP must match the offer address when that address is public and usable. Passive offers often carry a useless address (`PROTOCOL_SPEC.md` §7.2), so this cannot be universal.
- A mismatch policy is available: `RequireMatch`, `WarnOnly`. `WarnOnly` is the default, because of the above. Decision D7.

**Residual risk.** DCC has no in-band token, so the first connector wins during the window. Mitigated by a short window, a high port, and resume overlap checks. It cannot be eliminated, and is why active mode is preferred.

## 8. Integrity and confidentiality

| Mechanism | Detects | Does not detect |
|---|---|---|
| TCP checksum | Random corruption, weakly | Tampering |
| Size match | Truncation and overrun | Any same-length corruption or substitution |
| Resume overlap | Changed content inside the overlap | Changes elsewhere |
| Bot-supplied MD5 or filename CRC32 | Accidental corruption | A malicious sender, who controls the value |
| Host-supplied SHA-256 | Corruption and substitution | Limited only by how far the digest source is trusted |

The API reports which level was reached, as `IntegrityLevel`. `SizeOnly` means the structural checks passed, never that content is verified. Same-length corruption under `SizeOnly` is undetectable and ends as `Completed`. A host-supplied digest is the only strong option (`ARCHITECTURE.md` §7.5).

DCC is plaintext unless using SDCC, which itself does not verify certificates [S7]. The library emits `Warning::UnencryptedTransfer` once per transfer by default, and offers no setting that claims otherwise.

## 9. Secure defaults and interoperability cost

| Default | Interop cost | Override |
|---|---|---|
| Only requested offers | None for XDCC | None for SEC-1 |
| Exact nick match | Relay bots fail | `accept_nicks` per request |
| Deny private ranges | LAN bots fail | `allow_private_destinations` |
| Deny ports below 1024 | Rare, unverified | `allow_low_ports` |
| Refuse unknown size | Legacy senders fail | `allow_unknown_size`. Never yields `Completed`. |
| Refuse malformed or shifted offers | Senders with unusual numeric formats fail (Q9) | None |
| Size limit 64 GiB | Very large files fail | `max_file_size` |
| Passive off | Passive-only bots fail | `PassivePolicy::Enabled { .. }` |
| IRC TLS required | Plaintext-only networks fail | `allow_plaintext_irc` |
| IRC TLS verified | Self-signed networks fail | `CertPolicy::Pin(fingerprint)`. Disabling verification is explicit. |
| Honour STS [S9] | None | None |
| TSEND, SSEND refused | Rare | Later milestones |
| Auto-retry limited | Slower recovery | `RetryPolicy` |
| Plaintext DCC allowed | Accepted risk. It is the ecosystem baseline. | Warning event |

## 10. Resource limits

| Limit | Default |
|---|---|
| Inbound line | 8191 + 512 bytes |
| Offers per nick | 5 per minute |
| Unmatched offer memory | None retained |
| Concurrent transfers | 4 |
| Per-bot concurrent transfers | 1 |
| Max file size | 64 GiB |
| Read buffer | 256 KiB |
| Event ring | 256 per transfer. Oldest entries overwritten, never blocks. |
| Transfer mailbox | 64, overflow fails that attempt only |
| Storage job queue | 8 jobs per transfer |
| Storage worker threads | One per transfer, bounded by concurrent transfers |
| Reconciler threads | One per client, one job at a time |
| Reconciliation attempts | 8 per record, then only on host request. Records keep their transfer slot, so concurrent transfers bounds them. |
| Recovery jobs | None automatic. At most one queued per partial, only on host request. |
| IRC link channels | 256 inbound, 64 outbound |
| Finished outcomes retained | 1,024 |
| Filename input | 512 bytes |
| Bot notice retained | 512 bytes |

## 11. Logging and privacy

- `tracing` fields carry sanitised values. Raw bytes appear only at `trace`, and only in `Debug`-escaped form.
- SASL passwords and NickServ credentials are never logged. Secret types redact `Debug`.
- IP addresses are logged at `debug` and below.
- Sidecars record bot nick, network, and size. Hosts should treat them as user data.

## 12. Disclosure

A `SECURITY.md` at repository root with a contact method and a disclosure process is required before v0.1. Decision D8.

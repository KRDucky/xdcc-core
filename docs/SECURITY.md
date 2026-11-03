# XDCC Core Security Model

**Status:** Phase 0 draft, revised after independent review, 2026-10-31. §4, §5 and the offer rate limit describe the pure `policy` layer from M2, which is implemented and in PR review. `SafeName` and `ApprovedAddr` exist, but nothing uses them yet: no socket, file, or transfer code exists. Every other control here is design only, and the policy layer alone does not make a download safe. See `M2_REPORT.md`.

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
| T4 | Path traversal in filename | High | Critical | SEC-4, §5. Recent real example: CVE-2026-32733 in Halloy, a Rust client, through names like `../../.ssh/authorized_keys` [X4]. |
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

Implemented in `src/policy/`. `NetPolicy::check(addr, port)` is a pure function of its arguments and its configuration. It returns an `ApprovedAddr` or a named refusal.

### Decision order

1. Canonicalise, so `::ffff:a.b.c.d` is judged as IPv4.
2. Refuse port 0. Refuse ports below 1024 unless `allow_low_ports` is set. 1023 is refused and 1024 passes.
3. If the most specific built-in range is a transition range with a fixed layout, decode its embedded IPv4 address. Teredo yields two.
4. Refuse the never-allowed ranges, for the address and for each decoded one. No setting overrides these.
5. Refuse on an explicit `deny` rule that matches the address or a decoded one. Deny beats allow.
6. Find the most specific built-in range. It is cleared only by an `allow` rule that contains the address and is at least as long as that range, or by `allow_private_destinations` for the private class. So `0.0.0.0/0` clears nothing, and a metadata host needs an exact-host rule.
7. Put each decoded address through steps 4 to 6 as IPv4. All must pass.

Decoding never approves anything. It only adds refusals. So allowing `2002::/16` does not reach `2002:7f00:1::` unless loopback is also allowed.

### Built-in ranges

| Class | Ranges | Cleared by |
|---|---|---|
| Never allowed | `0.0.0.0/8`, `::/128`, `224.0.0.0/4`, `240.0.0.0/4` (includes broadcast), `ff00::/8` | Nothing |
| Loopback | `127.0.0.0/8`, `::1/128` | Allow rule only |
| Private | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`, `100.64.0.0/10` | `allow_private_destinations`, or allow rule |
| Link-local | `169.254.0.0/16`, `fe80::/10`, `fec0::/10` | Allow rule only |
| Metadata | See below | Exact-host allow rule only |
| Special-use | `192.0.0.0/24`, `192.0.2.0/24`, `198.18.0.0/15`, `198.51.100.0/24`, `203.0.113.0/24`, `2001:db8::/32`, `192.88.99.0/24`, `100::/64`, `100:0:0:1::/64`, `2001::/23`, `3fff::/20`, `5f00::/16`, and IPv6 outside `2000::/3` with no narrower entry | Allow rule only |
| Transition | `64:ff9b::/96`, `64:ff9b:1::/48`, `2002::/16`, `::/96`, `::ffff:0:0:0/96`, `2001::/32` | Allow rule only, and decoded addresses must also pass |

Other addresses are treated as public. `allow_private_destinations` relaxes the private class only. It does not reach loopback, link-local, metadata, special-use, or transition ranges, and never-allowed ranges cannot be relaxed at all. Loopback for tests and the simulated bot needs an explicit rule such as `127.0.0.1/32`.

`2000::/3` holds all global unicast, per IANA, so addresses outside it are never treated as public. That also catches the neighbours of the NAT64 prefixes. Some entries inside `2001::/23` and `192.0.0.0/24` are globally reachable in the IANA registries, and `64:ff9b::/96` is too. They are denied on purpose, because no DCC peer belongs there.

### Cloud metadata

Hosts inside a relaxed range stay refused, because each is a more specific entry. **The list is best-effort.** Other providers exist, and an address can change.

| Address | Provider | Evidence |
|---|---|---|
| `169.254.169.254` | AWS, Azure, GCP, Oracle | Each vendor's documentation |
| `fd00:ec2::254` | AWS | [Instance metadata retrieval](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html) |
| `fd20:ce::254` | GCP | [Metadata overview](https://docs.cloud.google.com/compute/docs/metadata/overview), checked in the page source on 2026-11-02 |
| `100.100.100.200` | Alibaba | [View instance metadata](https://www.alibabacloud.com/help/en/ecs/user-guide/view-instance-metadata) |

No entry is provisional. Two candidates are left out for lack of a documented purpose: `192.0.0.192` is absent from Oracle's page, though `192.0.0.0/24` refuses it anyway, and Azure's `168.63.129.16` appears only in sample output on the page read.

### Translation addresses

This resolves an ambiguity in the earlier table, which listed these prefixes as denied and also said their embedded IPv4 was re-evaluated. **They are denied whole by default.** The embedded address only adds refusals when an explicit rule admits the prefix.

| Prefix | Embedded IPv4 | Source |
|---|---|---|
| `64:ff9b::/96` | Bits 96 to 127 | RFC 6052 §2.2, /96 row |
| `2002::/16` | Bits 16 to 47 | RFC 3056 §2 |
| `::/96`, except `::` and `::1` | Bits 96 to 127 | RFC 4291 §2.5.5.1 |
| `::ffff:0:0:0/96` | Bits 96 to 127 | SIIT form |
| `2001::/32` | Server, bits 32 to 63. Client, bits 96 to 127 inverted. | RFC 4380 §4 |
| `64:ff9b:1::/48` | **Not decoded** | RFC 8215 says nodes must not assume embedded IPv4 exists or where it sits |

**Detection is not universal.** RFC 6052 lets an operator use a network-specific prefix of /32, /40, /48, /56, /64, or /96 inside global space, and those addresses look like any other. An address under such a prefix is judged as the IPv6 address it is. Only a deployment knows its own prefix, and it can add one as a `deny` rule.

### Rules and `ApprovedAddr`

`IpPrefix` refuses host bits and over-long lengths. A rule inside `::ffff:0:0/96` becomes its IPv4 form, so it matches the addresses it names. A shorter IPv6 rule that contains that range, such as `::/0`, is refused: addresses are canonicalised first, so it could never match the mapped addresses it appears to cover. Each list holds at most 256 rules.

`ApprovedAddr` has private fields and only `NetPolicy::check` builds it, which `compile_fail` tests pin. It records one policy decision for one endpoint at one moment. **It does not authenticate the peer, and it does not replace checking again.** The future `net` layer must call `check` immediately before connecting (SEC-2). Parsing an offer never produces one, and no policy function takes an offer type.

**Ports.** Whether any live bot listens below 1024 is unverified (`COMPATIBILITY.md` Q3). HexChat carries a similar check, commented out, which suggests it once caused a problem.

```rust
pub struct NetPolicyConfig {
    pub allow_private_destinations: bool,   // default false
    pub allow_low_ports: bool,              // default false
    pub deny: Vec<IpPrefix>,                // always wins
    pub allow: Vec<IpPrefix>,               // clears built-in ranges, as above
}
```

`PassivePolicy` arrives with passive support in M8.

**Why SSRF severity stands even with no attacker-chosen request body.** A DCC receiver writes ACK bytes to the destination and stores what it returns. This allows port scanning through timing, sending short binary junk to internal services, and storing a banner in a file.

## 5. Filename sanitising

Implemented in `src/policy/`. Output is a single path component, or a refusal. `WireName` is not changed, and RESUME keeps using it. Sanitising uses `WireName::name()`, the bytes without quotes.

Input is refused before anything is allocated if it is empty or over 512 bytes. It is then decoded lossily. Each invalid sequence becomes U+FFFD. A pass then runs until it stops changing, at most four times:

1. Normalise to NFC. This comes first because NFC can create ASCII: U+212A becomes `K`, and U+037E becomes `;`. Removal can also create a composable pair, which is why a later pass normalises again.
2. Keep the text after the last `/` or `\`. A trailing separator leaves nothing, which is refused.
3. Remove C0, DEL and C1 controls, soft hyphen, U+034F, U+061C, U+180E, U+200B to U+200F, U+2028 to U+202E, U+2060 to U+2064, U+2066 to U+2069, U+FEFF, U+FFF9 to U+FFFB, and tags U+E0000 to U+E007F.
4. Replace `< > : " | ? *` with `_`, plus the look-alike separators U+2044, U+2215, U+29F8, U+FF0F, U+FF3C and U+FE68. Colon blocks NTFS alternate data streams and drive forms.
5. Strip leading dots, spaces, and dashes. Strip trailing dots and spaces. Refuse an empty result, so `.` and `..` are refused.
6. Prefix `_` to a reserved stem. The stem is the text before the first dot, without trailing spaces, compared ignoring ASCII case: `CON`, `PRN`, `AUX`, `NUL`, `COM0`–`COM9`, `LPT0`–`LPT9`, `COM¹ COM² COM³`, `LPT¹ LPT² LPT³`, `CONIN$`, `CONOUT$`.
7. Refuse names ending in `.xdccpart`, `.xdccmeta`, or `.xdccmeta.tmp`, ignoring ASCII case. The last is the temporary sidecar from `ARCHITECTURE.md` §7.9.
8. Truncate to 200 UTF-8 bytes on a character boundary. An extension is kept if it has a non-empty stem and is at most 32 bytes, dot included. A longer one is treated as stem, so it is cut rather than preserved.

A result is accepted only if a further pass leaves it unchanged, and a separate predicate that shares no transformation code agrees it is valid. So sanitising an accepted name changes nothing, and truncation cannot leave a reserved name or suffix: if a pass exposes one, a later pass fixes or refuses it. If the passes do not settle, the name is refused.

This corrects the earlier order, which applied NFC last. That let normalisation produce characters the filters had already passed.

**Reserved names.** Microsoft's [naming documentation](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file) lists `COM¹²³` and `LPT¹²³`, which the earlier list omitted, and does not list `COM0` or `LPT0`, which it included. This list is the union. `COM0` and `LPT0` stay as portable caution. `CONIN$` and `CONOUT$` are not on that page, but Microsoft's [`RtlIsDosDeviceName_U`](https://learn.microsoft.com/en-us/windows/win32/devnotes/rtlisdosdevicename_u) page lists them as device names, and Windows treats them as devices (below). `COM⁴` (U+2074) is not reserved.

**Measured on Windows.** Microsoft's pages do not say how case is folded, so `tests/windows_device_names.rs` asks Windows directly. On hosted Server 2022 (build 20348) and Server 2025 (build 26100), every BMP code point was tried in each position of each reserved name and appended to it, in upper and lower case, inside a directory and as a bare name. Exclusive creation was also tried for the case variants. The only non-ASCII device names were `COM` and `LPT` followed by `¹`, `²` or `³`, which are already prefixed. Variants such as `conın$` (U+0131) were ordinary files, so comparing stems ignoring ASCII case only is correct on those builds. Server 2022 reserves every name, with or without an extension, in every directory, `CONIN$` and `CONOUT$` included. Server 2025 reserves only `NUL` inside a directory, and not `NUL.txt`, but still reserves every bare name. The list stays the union, because older Windows reserves every name everywhere. Windows 10 and 11 client builds were not tested.

**Accepted risk.** Invisible characters outside the list, such as Hangul fillers and variation selectors, are kept. Some removals, notably U+200C and U+200D, are ordinary in some scripts, so they can change or collide real names (Q11).

Percent sequences are not decoded, so `%2F` stays literal and cannot become a separator. KVIrc treats it as a separator. Decoding is the behaviour that creates risk, and leaving it as text is safe.

**What `SafeName` does not establish.** Sanitising causes collisions: `a?b` and `a*b` both become `a_b`, and `CON` and `_CON` both become `_CON`. A `SafeName` does not authorise overwriting and does not establish containment. Symlinks, races between check and create, exclusive creation, and case collisions on the target filesystem belong to storage work in M5 (SEC-4, SEC-5, §6). `SafeName` has private construction, with no default, conversion, parsing, deserialisation, or mutable accessor.

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
| Offers per nick | Sustained 5 per minute, burst 5, so at most 9 in any 60 s window |
| Offer rate keys tracked | 1,024 fingerprints in fixed memory. See below. |
| Unmatched offer memory | No offer content retained. See below. |
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

These are configuration values. `Limits::new` refuses unsafe settings, such as zeros and products that overflow. Validating a value does not enforce it. The filename input limit and the offer rate are implemented in `policy`, but no caller exists, so they take effect only when M5 and M6 use them. The inbound line limit is in `LineFramer`. The others name what later layers must enforce, and those layers do not exist yet.

**Offer rate limiter.** It uses GCRA over integer milliseconds, with time passed in by the caller, and reads no clock. "5 per minute" is a sustained rate with a burst of 5, not a hard cap: 5 at once, then one every 12 s, so a nick can reach 9 in one 60 s window. A hard cap would need a timestamp log per nick. Time that runs backwards neither refills nor panics.

**What is retained for unmatched offers.** The limiter keeps no nick, filename, or address, but it does keep a keyed 64-bit fingerprint of each nick it is asked about, with one arrival time, in a table fixed at creation. This corrects the earlier "none retained" for anything the limiter sees. The engine should consult the limiter only after matching an offer to a request, so unrequested offers never occupy a slot. M6 must hold to that.

**Flood behaviour.** A slot is reclaimed only once its bucket has fully refilled, so a flood cannot reset an attacker's budget. A nick with no slot shares one overflow bucket, and a nick claiming a new slot starts from that bucket's state, so a nick that spent shared budget cannot take a fresh slot. **The cost:** once the shared bucket is spent, every new nick waits for up to one window, even if slots are free, and that includes a requested bot. Nicks already tracked are unaffected.

**CASEMAPPING changes.** Fingerprints cannot be recomputed. Nicks with no byte that folds differently keep their fingerprint and are unaffected. Nicks with such a byte, tracked or new, have no spare budget until every bucket from before the change has refilled.

## 11. Logging and privacy

- `tracing` fields carry sanitised values. Raw bytes appear only at `trace`, and only in `Debug`-escaped form.
- SASL passwords and NickServ credentials are never logged. Secret types redact `Debug`.
- IP addresses are logged at `debug` and below.
- Sidecars record bot nick, network, and size. Hosts should treat them as user data.

## 12. Disclosure

A `SECURITY.md` at repository root with a contact method and a disclosure process is required before v0.1. Decision D8.

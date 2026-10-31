# XDCC Core Protocol Specification (Draft)

**Status:** Phase 0 draft, revised after independent review, 2026-10-31. No part of this has been tested against a live bot.

No normative specification exists for XDCC, for DCC RESUME, or for DCC ACK behaviour above 4 GiB. This document records what is known, how it is known, and what XDCC Core will do. Sections labelled **Rule** define this project's behaviour. They are design decisions, not claims about the wider ecosystem.

## 1. Evidence levels

Every protocol claim carries one of these tags.

| Tag | Meaning |
|---|---|
| **[S]** | Published specification text (RFC, IRCv3, expired draft, or a historical spec) |
| **[V]** | Vendor documentation or changelog describing that vendor's own behaviour |
| **[I]** | Observed in implementation source at a pinned commit. Proves that implementation only. |
| **[M]** | Derived from an independent behavioural model in `docs/research/`. Not run against the real program. |
| **[?]** | Unverified. Must not be relied on until evidence exists. |

"Documented" means [S] or [V]. "Convention" means [I] across several independent implementations. "Extension" means [I] or [V] in a subset of implementations.

## 2. References

### Specifications and vendor documents

| ID | Source | Notes |
|---|---|---|
| S1 | [RFC 2812](https://www.rfc-editor.org/rfc/rfc2812.txt) | IRC client protocol, Informational. §2.3 framing, §3.3.2 NOTICE. |
| S2 | [Modern IRC docs](https://modern.ircdocs.horse/) | Living document, not a standard. |
| S3 | [CTCP spec, Mesander 1994](https://www.irchelp.org/protocol/ctcpspec.html) | Historical. Defines quoting that later work abandoned. |
| S4 | [DCC spec, Rollo](https://www.irchelp.org/protocol/dccspec.html) | Historical. Original 4-byte ACK rule. |
| S5 | [draft-oakley-irc-ctcp-02](https://datatracker.ietf.org/doc/html/draft-oakley-irc-ctcp-02) | Expired individual draft, Jan 2018. No IETF standing. |
| S6 | [Modern CTCP](https://modern.ircdocs.horse/ctcp.html) | States it is out of date in favour of S5. |
| S7 | [Modern DCC](https://modern.ircdocs.horse/dcc.html) | Self-described work in progress that "may be ENTIRELY INACCURATE". RESUME and ACCEPT sections are unwritten. |
| S8 | [IRCv3 Message Tags](https://ircv3.net/specs/extensions/message-tags) | 4094-byte tag limits. Rest of the message stays 512 bytes. |
| S9 | [IRCv3 STS](https://ircv3.net/specs/extensions/sts) | Strict Transport Security policy. |
| V1 | [mIRC DCC Resume Protocol](https://www.mirc.co.uk/help/html/dcc_resume_protocol.html) | Vendor help page. The only primary source for RESUME. |
| V2 | [mIRC versions.txt](https://www.mirc.com/versions.txt) | v5.4 passive protocol. v6.0, v6.1, v6.11 resume changes. v6.33 64-bit ACK rule. |

### Implementations read as behavioural references

No code from these projects is used or copied. Paths are relative to each repository. Full commit hashes, licences, and reproduction steps are in `research/README.md`.

| ID | Project | Role | Pinned commit | Date |
|---|---|---|---|---|
| I1 | [iroffer-dinoex](https://github.com/dinoex/iroffer-dinoex) | Bot (sender) | `c4dbbee` | 2026-08-16 |
| I2 | [irssi](https://github.com/irssi/irssi) | Client | `43f1727` | 2026-01-27 |
| I3 | [HexChat](https://github.com/hexchat/hexchat) | Client | `b544ac3` | 2024-02-09 |
| I4 | [WeeChat](https://github.com/weechat/weechat) | Client | `c07415d` | 2026-10-29 |
| I5 | [KVIrc](https://github.com/kvirc/KVIrc) | Client | `d1de244` | 2026-06-13 |
| I6 | [xdccJS](https://github.com/JiPaix/xdccJS) | XDCC library | `1dd7805` | 2025-01-27 |
| I7 | [xget](https://github.com/mario-campos/xget) | XDCC CLI | `3c00207` | 2023-02-25 |

### Secondary sources

| ID | Source | Use |
|---|---|---|
| X1 | [irc-dcc (Haskell) docs](https://hackage.haskell.org/package/irc-dcc-2.0.1/docs/Network-IRC-DCC.html) | Independent listing of reverse-DCC formats |
| X2 | [irssi issue #977](https://github.com/irssi/irssi/issues/977) | User report: >4 GiB transfers failing near the end. Cause never established. |
| X3 | [GNU bug #59135](https://debbugs.gnu.org/db/59/59135.html) | ERC >4 GiB ACK overflow, and senders enabling turbo silently |
| X4 | [GHSA-fqrv-rfg4-rv89](https://github.com/squidowl/halloy/security/advisories/GHSA-fqrv-rfg4-rv89) | CVE-2026-32733, path traversal in Halloy, a Rust IRC client |
| X5 | [NAT-Again](https://dgl.cx/2022/08/nat-again-irc-cve-2022-2663) | CVE-2022-2663, `nf_conntrack_irc` DCC matching |
| X6 | [Wikipedia: XDCC](https://en.wikipedia.org/wiki/XDCC) | Origin of XDCC only. Article is flagged as needing citations. |

## 3. IRC framing

**Documented.**

- Messages are CRLF-terminated and at most 512 bytes including CRLF [S1 §2.3].
- With IRCv3 tags, tag data may add up to 8191 bytes. The non-tag portion stays limited to 512 bytes [S8].
- Grammar is `[":" prefix SPACE] command [params] crlf` [S1 §2.3.1].
- Automatic replies must never be sent in response to a NOTICE [S1 §3.3.2].
- Software should use UTF-8, but IRC is byte-oriented and legacy encodings persist [S2].

**Rule.**

1. Parsing operates on `&[u8]` and never requires UTF-8. Filenames stay as bytes until sanitised.
2. Accept lone LF as a terminator on input [S2]. Always send CRLF.
3. Reject outbound lines containing CR, LF, or NUL at construction time.
4. Compare nicks using the server's advertised `CASEMAPPING`, defaulting to `rfc1459`. [?] The default is a project decision, and the exact values should be confirmed from S2's ISUPPORT section during M1.
5. Budget outbound length conservatively, because the relayed line gains a `:nick!user@host ` prefix that the sender cannot see exactly. Overlong outbound lines fail with an explicit error rather than being truncated.

**Truncation hazard.** A long filename can push a relayed `DCC SEND` beyond 512 bytes, so a server may cut off the trailing fields. A truncated offer can parse as a shorter but well-formed one, and a cut size field is still a valid number. See §7.4.

## 4. CTCP

**Documented.**

- A CTCP message is a PRIVMSG or NOTICE body delimited by `0x01` [S3, S5].
- The final delimiter should be sent, but receivers must accept messages lacking it [S5, S6].
- Queries use PRIVMSG and replies use NOTICE [S6].
- Low-level (`0x10`) and CTCP-level (backslash) quoting appear in S3. S5 says implementations SHOULD NOT implement them [S5].
- Mixing plain text and tagged chunks was specified in S3 and is not widely implemented [S6].

**Observed.** iroffer accepts `XDCC` both as plain text and as a CTCP tag, along with the alias `CDCC`, in `src/dinoex_user.c` (handling at line 1566). I5 treats `DCC`, `XDCC`, and `TDCC` as DCC tags (`KviIrcServerParser_ctcp.cpp:826`).

**Rule.**

1. A message is CTCP only if the body's first byte is `0x01`. An embedded `\x01DCC ` elsewhere in a message is plain text. CVE-2022-2663 shows why loose matching is dangerous [X5].
2. The body ends at the next `0x01` or end of message. The parser records whether the final delimiter was present, and whether the line reached the truncation threshold (default 480 bytes excluding CRLF). §7.4 uses both.
3. Apply neither quoting layer on input or output.
4. Tag and DCC type matching is ASCII case-insensitive [I1, I3].
5. A `DCC` offer is accepted only from PRIVMSG addressed to our own nick. A DCC offer in NOTICE or to a channel is logged and ignored. [?] Whether any live bot offers over NOTICE is unknown.
6. The library never answers CTCP queries itself. VERSION, PING, and similar are the host's concern, and the built-in client drops `0x01` from anything it echoes [X5].

## 5. XDCC commands

XDCC began in 1994 as an ircII script and now loosely names bot file-serving software [X6]. It has no specification. The table below is **iroffer-dinoex behaviour only** [I1], from `command_xdcc` in `src/dinoex_user.c`. Other bot software may differ.

| Command | Purpose | Notes |
|---|---|---|
| `XDCC SEND <pack>` | Request a pack | `GET` is an alias |
| `XDCC BATCH <range>` | Request several packs | Only when `send_batch` is configured |
| `XDCC LIST` | Request listing | Often restricted |
| `XDCC INFO <pack>` | Pack metadata | Can be disabled by configuration |
| `XDCC SEARCH <pattern>` | Search | |
| `XDCC QUEUE` | Show own queue position | |
| `XDCC CANCEL` | Abort own transfer | Named in the bot's reminder notice |
| `XDCC REMOVE [n]` | Leave queue | |
| `XDCC OPTION <name>` | Per-nick options | `IPV4`, `IPV6`, `ACTIVE`, `PASSIVE`, `QUIET` |
| `XDCC STOP`, `OWNER`, `HELP` | Miscellaneous | |

**Pack syntax** [I1, `packnumtonum` in `src/dinoex_misc.c`]: `#5`, `5`, and `[CRC]` forms exist. Clients differ: I7 sends `XDCC SEND #%u`, and I6 sends `xdcc send %d`. iroffer upper-cases the command before matching. A lock password parameter exists (`check_lock`), but its argument position was not confirmed.

**Rule.** Send plain PRIVMSG `XDCC SEND #<n>`. Form and case are configurable by profile, because [?] other bot families are not verified.

## 6. Bot notices

Notices are free-form human text. iroffer ships language tables (`Lang/`) and owners can customise some messages, so wording cannot be treated as a protocol.

Strings below are from I1 and describe English iroffer-dinoex only.

| Class | Example text |
|---|---|
| Starting | `** Sending you pack #%u ("%s")`, `** Sending you queued pack #%u ("%s")` |
| Queued | `Added you to the main queue for pack %u ("%s") in position %u. To Remove yourself at ...` |
| Slots full | `** All Slots Full, %s`, `** You can only have %u %s at a time, %s` |
| Denied | `** XDCC SEND denied, this pack is locked`, `** XDCC %s denied, you must be on a known channel to request a pack` |
| Invalid | `** Invalid Pack Number, Try Again` |
| Duplicate | `** You already requested that pack` |
| Limit | `** Sorry, This Pack is over download limit for today.  Try again tomorrow.` |
| Pending | `** You have a DCC pending, Set your client to receive the transfer. Type "/MSG %s XDCC CANCEL" to abort the transfer. (%li seconds remaining until timeout)` |
| Closed | `** Closing Connection: %s`, for example `Pack file changed`, `You are no longer on a known channel` |
| Finished | `** Transfer Completed (... md5sum: %s)` when an MD5 is known |

**Rule.**

1. Notices are advisory. They may update queue display, and they may provide a *hint* for error classification.
2. A notice can never move a transfer to `Completed`, and never starts a connection.
3. Failure to recognise a notice is not an error. It surfaces as `BotNotice { text }`, with control bytes neutralised.
4. An MD5 from a notice is an optional integrity input. It comes from the same untrusted party as the data, so it detects corruption, not malice.

## 7. DCC SEND

### 7.1 Wire format

```
DCC SEND <filename> <address> <port> [<size> [<token>]]
```

| Field | Evidence |
|---|---|
| Address, port, size are ASCII decimal, unsigned long, unsigned short, unsigned long | [S3] |
| Size is optional, and old clients may omit it | [S3] |
| Size may exceed 32 bits | [V2 v6.33, I1, I2, I3, I4] |
| Token is a fifth field, used in passive mode | [V2 v5.4, I1–I6, X1] |

The original spec discourages auto-accepting offers [S3]. XDCC clients auto-accept by nature, because the user asked for the transfer, which makes request correlation the central safety control (`SECURITY.md`).

### 7.2 Address field

| Form | Evidence |
|---|---|
| IPv4 as decimal integer, network byte order value | [S3, S7, I1–I5] |
| IPv6 as textual address | [S7, I1, I2, I5]. I3 stores the address in a `guint32` and cannot represent it. I6 supports it in alpha form for passive only. |
| Dotted-quad IPv4 | Accepted by I5 (`dcc_module_normalize_target_data`) |
| Hostname | Not observed. [?] |

**Passive offers may carry a meaningless address.** HexChat literally sends `199` (`dcc.c:1887`), and mIRC sends its SOCKS firewall address [V2]. Treat the address as unusable in a port-0 offer. No connection is ever made to it.

**Rule.** Parse decimal IPv4, textual IPv6, and dotted IPv4. Never resolve a hostname from an offer. A value containing a colon is IPv6 [I2 `dcc_str2ip`].

### 7.3 Filename

Observed conventions:

- Filenames with spaces are wrapped in `"..."` [I1 `getsendname`, I2, I3, I6]. No escape for an embedded quote is documented anywhere found.
- Some senders replace spaces with `_`, since iroffer's `spaces_in_filenames` is configurable [I1].
- iroffer substitutes `_` for `| : ? * < > / \ " ' \`` and DEL in names it sends [I1].
- I2 tolerates unquoted spaces, by scanning for the numeric tail.
- I4 finds the closing quote with `strrchr`.
- Sent names should be a base name [S3], but this cannot be relied on. CVE-2026-32733 was exactly that assumption [X4].
- I5 treats `%2F` as a path separator too (`requests.cpp`).

**Rule.** Keep two values that are never confused:

- `wire_name`: the exact bytes and quoting received, echoed verbatim in RESUME.
- `safe_name`: the sanitised output used on disk (`SECURITY.md` §5).

Sanitising before echoing would change what the bot sees. iroffer happens to match leniently, but no other sender's matching is known in full.

### 7.4 Parsing algorithm

The earlier "evaluate every shape, then break ties" design was wrong. It rejected a documented valid offer as ambiguous, and it let a malformed standard offer fall through to the legacy shape. This replacement is deterministic.

**Principles.**

- The shape is chosen **first**, from token count and one literal check. Field values are validated **afterwards**.
- A field that fails validation refuses the whole offer. There is no fallback to another shape.
- Only the filename can contain spaces, so an unquoted filename is everything left of the tail.

**Terms.**

- *Number:* one or more ASCII digits, at most 20 characters, within the field's range. `-1`, `+5`, `1k`, and an empty field are not numbers.
- *Zero-valued:* a number equal to 0, such as `0` or `00`.
- *Tokens:* `args` split on runs of spaces, numbered `t[1]` to `t[k]`. Leading and trailing spaces are ignored. Spaces inside an unquoted name are kept exactly in `wire_name`.

**Shape selection.**

| Form | Condition | Shape | Tail |
|---|---|---|---|
| Quoted | 2 tail fields | Legacy | `<addr> <port>` |
| Quoted | 3 tail fields | Standard | `<addr> <port> <size>` |
| Quoted | 4 tail fields, second is zero-valued | Passive | `<addr> 0 <size> <token>` |
| Quoted | 4 tail fields, second is not | Refuse `UnexpectedToken` | |
| Quoted | Any other count | Refuse `BadFieldCount` | |
| Unquoted | `k < 3` | Refuse `TooFewFields` | |
| Unquoted | `k == 3` | Legacy | `t[2] t[3]` |
| Unquoted | `k >= 5` and `t[k-2]` is zero-valued | Passive | last 4 tokens |
| Unquoted | Otherwise (`k >= 4`) | Standard | last 3 tokens |

A value starts as quoted if `args` begins with `"`. The closing quote is the last `"` followed by a space. If there is none, refuse with `UnterminatedQuote`. An empty name refuses with `EmptyName`. A quoted token cannot be confused with the tail, because a token may not contain `"`.

**Field validation, in order.** The order fixes which error is reported. Every outcome is a refusal.

| Shape | Order |
|---|---|
| Standard, Legacy | `PortZeroWithoutToken`, `BadPort`, `BadAddress`, `ImplausibleAddress`, `BadSize` |
| Passive | `BadAddress`, `BadToken`, `BadSize` |

- **Address:** IPv4 as a decimal number up to `2^32 - 1`, dotted-quad IPv4, or textual IPv6. Anything else is `BadAddress`, including hostnames.
- **`ImplausibleAddress`:** an active offer with an IPv4 address in `0.0.0.0/8`. A real active sender needs a routable address, and a port-sized number in the address position means the fields have shifted. It is a parser refusal, and `allow_private_destinations` does not bypass it.
- **Passive address:** must be syntactically valid but is never connected to. A value in `0.0.0.0/8`, like HexChat's `199`, yields `claimed_addr = None`.
- **Token:** 1 to 64 bytes of printable ASCII, excluding space and `"`.
- **Size:** 0 to `2^64 - 1`. Zero is valid (§10.1).

**Truncation.**

| Condition | Result |
|---|---|
| No final `0x01`, Legacy shape | `SuspectedTruncation`, since a cut offer looks like a size-less one |
| No final `0x01`, line at the truncation threshold, any shape | `SuspectedTruncation`, since a cut size field is still a number |
| No final `0x01`, short line, Standard or Passive | Accepted, as S5 requires |

**Why the grammar is unambiguous.**

- Legacy and the other unquoted shapes are disjoint, because Legacy needs `k == 3` and the others need `k >= 4`.
- Passive and Standard are disjoint. Passive needs `t[k-2]` to be zero. In the Standard shape `t[k-2]` is the address, and a zero address is refused. So passive precedence never takes an offer that Standard would accept.
- Nothing falls back, so a malformed standard offer cannot become a legacy or passive one.
- `AmbiguousOffer` no longer exists.

**Compatibility behaviour, chosen deliberately.**

| Input | Behaviour | Other software | Cost |
|---|---|---|---|
| Legacy with an unquoted multi-word name | Refused | I2 scans for a numeric tail | Pre-size senders with spaces. Their era predates quoting. |
| Nonzero port plus token | Refused | I2 and I3 treat it as the reply step when *they* are the sender | None for a receiver. A bot sending this was not observed. |
| Unquoted name ending in digits | Parsed as Standard, name keeps the digits | Varies | None |
| Negative numbers | Refused | Q9 is open | Unknown until a corpus exists |

An attacker can always craft a well-formed offer, so correct parsing is not a trust decision. `SECURITY.md` applies after this.

**Vectors.** `research/offer_parser_check.py` holds the executable set, 35 vectors plus generated round trips. Representative cases:

| Input after `SEND` | Result |
|---|---|
| `file.bin 3232235777 5000 1024` | Standard, name `file.bin` |
| `"a b.bin" 3232235777 5000 1024` | Standard, name `a b.bin`, wire form keeps quotes |
| `a b.bin 3232235777 5000 1024` | Standard, name `a b.bin`, wire form unquoted |
| `report 2024 3232235777 5000 1024` | Standard, name `report 2024` |
| `f.bin 3232235777 5000 99999999999` | Standard, size exceeds 32 bits |
| `f.bin 3232235777 5000 0` | Standard, zero-length file |
| `f.bin 2001:db8::1 5000 1024` | Standard, IPv6 |
| `file.bin 199 0 1024 77` | Passive, token `77`, `claimed_addr = None` |
| `a b.bin 199 0 1024 77` | Passive, name `a b.bin` |
| `f.bin 3232235777 5000` | Legacy, `size = None`, refused later by default policy |
| `"a b.bin" 3232235777 5000` | Legacy, `size = None` |
| `f.bin 3232235777 70000 1024` | `BadPort`, **never** legacy |
| `f.bin 3232235777 -5000 1024` | `BadPort` |
| `f.bin 3232235777 abc 1024` | `BadPort` |
| `f.bin 3232235777 5000 -1` | `BadSize` |
| `f.bin 3232235777 5000 1k` | `BadSize` |
| `f.bin 3232235777 5000 18446744073709551616` | `BadSize`, overflows 64 bits |
| `f.bin 4294967296 5000 1024` | `BadAddress`, overflows 32 bits |
| `f.bin host.example 5000 1024` | `BadAddress`, hostnames are not resolved |
| `f.bin 5000 1024 77` | `ImplausibleAddress` |
| `f.bin 3232235777 5000 1024 77` | `ImplausibleAddress`, shifted fields |
| `"f.bin" 3232235777 5000 1024 77` | `UnexpectedToken` |
| `f.bin 3232235777 0 1024` | `PortZeroWithoutToken` |
| `a b.bin 3232235777 5000` | `BadPort`, legacy with spaces is unsupported |
| `f.bin 3232235777` | `TooFewFields` |
| `"a b.bin 3232235777 5000 1024` | `UnterminatedQuote` |

A refused offer never reaches network or filesystem code.

### 7.5 Parsing RESUME and ACCEPT

Only ACCEPT is received by this library. It is matched against the state of the pending attempt, so the parser is told which tail to expect.

| Pending attempt | Expected tail |
|---|---|
| Active | `<port> <position>` |
| Passive | `0 <position> <token>` |

Quoted names use the same closing-quote rule. Unquoted names take everything left of the expected tail. The name is not compared (§9), so a `file.ext` or rewritten name is harmless. Number and token rules match §7.4, and any failure ignores the message and counts it.

## 8. Passive (reverse) DCC

**Vendor-documented** [V2 v5.4]. A port of zero plus a trailing unique id marks a passive request. The other party opens a listening socket and replies with the same id. RESUME and ACCEPT are extended by appending the id.

```
Sender   -> Receiver : DCC SEND <name> <addr> 0 <size> <token>
Receiver             : listen on <ourport>
Receiver -> Sender   : DCC SEND <name> <ourip> <ourport> <size> <token>
Sender   -> Receiver : TCP connect to <ourip>:<ourport>
```

Passive resume ordering is documented in a KVIrc source comment (`dccModuleParseDccSend`, `requests.cpp`), and matches I1 and I2:

```
Sender   -> Receiver : DCC SEND   <name> <addr> 0 <size> <token>
Receiver -> Sender   : DCC RESUME <name> 0 <position> <token>
Sender   -> Receiver : DCC ACCEPT <name> 0 <position> <token>
Receiver -> Sender   : DCC SEND   <name> <ourip> <ourport> <size> <token>
Sender   -> Receiver : TCP connect
```

Observations:

- iroffer's token is its transfer id, so it is a small predictable integer [I1 `t_start_dcc_send`].
- irssi uses `rand() % 64` for its id [I2 `dcc-send.c:441`]. Tokens are correlation values, not secrets.
- The token is **not** present on the TCP connection. An inbound connection cannot be bound to a token (`SECURITY.md` §7).
- HexChat requires `pasvid != 0` in a passive offer (`handle_dcc`). This project treats `0` as valid only if a real bot produces it. [?]
- iroffer accepts passive mode by global `passive_dcc` or per-nick `XDCC OPTION PASSIVE` [I1].
- Passive mode requires the receiver to know its own reachable address. S7 says it must not derive it from `RPL_WELCOME`.

**Rule.** The token is an opaque byte string, at most 64 bytes, echoed verbatim. The caller supplies the advertised address. The library does not guess a public IP.

## 9. RESUME and ACCEPT

**Vendor-documented** [V1]:

```
Receiver -> Sender : DCC RESUME <filename> <port> <position>
Sender -> Receiver : DCC ACCEPT <filename> <port> <position>
```

The receiver then connects to the address and port from the original offer, and data begins at `position`.

**Filename field.** Older mIRC sent the literal `file.ext`. Since v6.1, mIRC uses the original filename [V2]. V1 says newer versions ignore the name since the port identifies the connection. V1's text still describes `file.ext`, so it predates or conflicts with the changelog in that detail.

**Matching in practice.**

| Software | How RESUME or ACCEPT is matched |
|---|---|
| iroffer | Nick, then case-insensitive substring of filename or port, then falls back to guessing the first candidate from that nick (`t_find_resume`) |
| irssi | Nick plus port, and passive id must match |
| HexChat | Port or passive id, then nick plus filename. ACCEPT by port only. |
| xdccJS | Nick only |

**Sender rejection.** iroffer refuses `position >= size` with a notice and sends no ACCEPT. So requesting resume at exactly the file size will time out. The bot's `ACCEPT` echoes the receiver's position string verbatim.

**Historic mIRC behaviour.** mIRC chops the last 8192 bytes of the partial file on resume "in case the end of the file was corrupted during a previous transfer" [V2 v6.0], applied only once the transfer begins [V2 v6.11]. This is precedent for resuming earlier than the partial length.

**Rule.**

1. Echo `wire_name` verbatim, and the original port or `0` plus token.
2. Match ACCEPT on nick and port or token. Do not compare filenames, since senders may rewrite them [I1].
3. `position` in ACCEPT must equal the requested position. A mismatch aborts the attempt with the partial file unchanged.
4. An unsolicited ACCEPT is ignored and counted.
5. If the trusted prefix `E` exceeds `size`, fail with `ResumeMismatch`. Never truncate to fit.
6. With overlap limit `O`, compute `Vt = min(O, E)` and `P = E - Vt`, then:

| Case | Action |
|---|---|
| `P > 0` | Send RESUME at `P` |
| `P == 0` | Send no RESUME. Connect as a fresh transfer, and verify the first `Vt` bytes as they arrive. |
| `E == size`, `size > 0`, `O == 0` | No network transfer. Go to verification and send best-effort `XDCC CANCEL`. |
| `E == size`, `size > 0`, `O > 0` | RESUME at `P < size`, which iroffer accepts. No new bytes are written. |

7. Overlap verification compares received bytes with the existing file before anything is written. A mismatch fails with `ResumeMismatch`, and the partial stays byte-identical.

Exact accounting and edge cases are in `ARCHITECTURE.md` §7.6.

## 10. Data phase and acknowledgements

**Documented.** The original rule is a cumulative count of received bytes as a 4-byte network-order integer, per packet [S3, S4]. The sender should wait for acknowledgement before continuing, and should not close until the last byte is acknowledged [S4]. The recipient cannot itself know the file is complete without a size [S4].

**Reality.**

- mIRC's sender has run ahead of ACKs since v6.33 and transfers "even if it receives no acks at all" [V2].
- HexChat, WeeChat, and KVIrc have fast-send modes.
- WeeChat as receiver disables ACKs if the socket buffer fills (`xfer-dcc.c`).
- xget offers `--no-acknowledge`.
- iroffer does not wait per-packet. After sending it enters `WAITING` and closes when `lastack >= size`, or on its timeout of 180 seconds without contact [I1 `t_flushed`, `t_istimeout`].

**Absolute versus relative on resume.** I2, I3, and I4 report absolute file position. HexChat carries an "fix for BitchX" branch for receivers whose ACKs are relative to the resume point (`dcc_handle_new_ack`). So relative ACKs existed in the wild.

**Rule.**

1. ACKs are absolute file positions, big-endian.
2. **No ACK before data.** An ACK may be sent only after at least one byte of this attempt has been verified or written, so its value always exceeds the request position. KVIrc sends one at connection on resume (`DccFileTransfer.cpp:314`), which triggers a mis-detection in iroffer (§11.3).
3. ACKs are coalesced, and sent after a read batch, at a byte threshold, and at a time threshold.
4. ACKs are written on a path that cannot stall the receive path. Only the newest value matters, but a started frame is always finished so the stream stays aligned.
5. The final ACK is sent as soon as the validated position reaches `size`, whether the last byte was written or verified. The receiver then reads until EOF or a grace timer.
6. Data past `size` is never written. It fails with `Overrun` if it arrives before completion.
7. ACKs are advisory bookkeeping. Nothing in the receiver depends on the peer's use of them.
8. The ACK value is the validated position defined in `ARCHITECTURE.md` §7.6. Bytes that fail overlap verification are never acknowledged.

### 10.1 Zero-length files

Evidence is thin and inconsistent. mIRC fixed zero-byte transfers in v6.33 [V2]. HexChat refuses an offer with size 0 (`handle_dcc`). iroffer warns about 0-byte packs when loading [I1].

**Rule.** A size-0 offer is valid. The receiver sends no RESUME and no ACK, because there is no data to acknowledge. It connects, drains until EOF or the grace timer, then verifies and publishes an empty file. Whether any live bot offers one is Q17.

## 11. Large files and ACK width

### 11.1 Documented behaviour

mIRC v6.33 (2008) [V2]:

> If mIRC sees that it is sending or receiving a file with a size larger than a 32-bit value, it sends and expects to receive 64-bit acks. In all other respects, the protocol is unchanged.

This is the only explicit protocol statement found on ACK width. It describes mIRC, and it does not establish what any other sender does.

### 11.2 Observed ACK behaviour

| Implementation | Receiver sends | Sender accepts |
|---|---|---|
| mIRC 6.33+ | 8 bytes when size > 32 bits [V2] | 8 bytes in that case [V2] |
| iroffer-dinoex | n/a | Auto-detects, or forces 8 bytes with `mirc_dcc64` [I1] |
| irssi | 4 bytes, low word | Compares low word |
| HexChat | 4 bytes, low word | Low word with reconstruction |
| WeeChat | 4 bytes, `htonl` of position | Compares truncated value to full size, so [?] sending above 4 GiB may never complete. Not tested. |
| KVIrc | 4 bytes by default, 8 bytes only with a non-default option and size > 32 bits | 4 bytes with rollover counting |
| xdccJS | 8 bytes when size > 4294967295, else 4 | n/a |

### 11.3 iroffer-dinoex detection

iroffer's default config is automatic. `verify_acknowlede` in `src/dinoex_transfer.c` inspects the **first** 4-byte value received:

- If `firstack <= startresume` and the file exceeds 32 bits, it decides the peer sends 8-byte ACKs, on the reasoning that the high word of a 64-bit count is zero or small.
- Otherwise it stays in 4-byte mode, and adds `2^32` whenever a value goes backwards.

The heuristic is sound for a fresh transfer. It misfires when a 4-byte peer's first value is at or below the resume point, which happens in two cases.

Results from the behavioural model `research/ack_behaviour_model.py` [M], for a 6 GiB file. The model encodes the behaviour described above, and its assumptions are listed in `research/README.md`.

| Case | Forced 8-byte | Final state correct | `lastack >= size` too early |
|---|---|---|---|
| Fresh, 4-byte wrapping | no | yes | no |
| Fresh, 8-byte | yes | yes | no |
| Fresh, 4-byte **with initial ACK of 0** | yes | **no** | **yes** |
| Resume at 1 GiB, 4-byte | no | yes | no |
| Resume at 1 GiB, 8-byte | yes | yes | no |
| Resume at 1 GiB, 4-byte **with initial ACK at offset** | yes | **no** | **yes** |
| Resume at 5 GiB, 4-byte wrapping | yes | **no** | **yes** |
| Resume at 5 GiB, 8-byte | yes | yes | no |
| Resume at 5 GiB, 8-byte with initial ACK | yes | yes | no |
| `mirc_dcc64` set, 4-byte | n/a | **no** | **yes** |
| `mirc_dcc64` set, 8-byte | n/a | yes | no |

These claims have different standing, and must stay separate:

| Claim | Standing |
|---|---|
| iroffer-dinoex contains this first-ACK heuristic | **Source-derived [I]** at the pinned commit |
| The heuristic misclassifies the rows in bold | **Modelled [M]**, from that source reading. Not observed on a running bot. |
| A falsely high value makes the bot stop waiting for the final ACK | **Source reading [I]**. `t_flushed` runs in `WAITING`, so the send continues, but the bot then closes as soon as everything is queued. It closes with `shutdown(SHUT_RDWR)` then `close`. |
| This causes real-world reset failures | **Unverified hypothesis [?]**, below |

**Hypothesis, unconfirmed [?].** If unread ACK bytes sit in the bot's receive queue at close, the kernel may send RST, which can destroy tail data still in flight. That would fit reports of ">4 GiB fails in the last few bytes with connection reset" [X2], but fitting is not evidence. Nobody has established this cause, and the reports may have another explanation. Experiment E1 tests it on a self-hosted bot (`DEVELOPMENT_PLAN.md` §2).

The sample config for iroffer says `mirc_dcc64` works only with mIRC 6.33+, and that XChat and irssi work only in 32-bit mode, which agrees with the table.

### 11.4 Rule (provisional)

**This default is provisional.** It is a working assumption for the simulator and for design. It must not be frozen until experiment E1 has run and the owner has decided D9.

| File size | Default ACK | Basis | Standing |
|---|---|---|---|
| `<= 0xFFFFFFFF` | 4 bytes | S4, every implementation read | Settled for design |
| `> 0xFFFFFFFF` | 8 bytes | V2 rule, xdccJS agrees, correct in every modelled iroffer case | **Provisional** |

No value is universally safe. 4-byte ACKs fail in modelled iroffer cases, and 8-byte ACKs are unproven against senders that frame in 4 bytes. By reading, irssi and HexChat should tolerate them, because low words arrive aligned and high words are ignored, but that has not been run. KVIrc as a sender may count high-word values as rollovers. This is Q1. Profiles can force a width.

Vendor documentation and simulated passes do not establish this rule for other software.

**Receiver integrity is independent of this choice.** ACK width can break the *sender's* accounting. It can never make the receiver believe a file is complete, because completion is computed locally (`ARCHITECTURE.md` §7.5).

## 12. Cancellation and timeouts

No specification defines these. iroffer's values [I1], which are not universal:

| Event | Behaviour |
|---|---|
| Waiting for connection | Reminder notices at 30, 90, 150 seconds. Closes at 180 seconds. |
| Offer retransmission | Reminders may resend `DCC SEND`, if `reminder_send_retry` is set |
| Any active transfer | Closes after 180 seconds without contact |
| User leaves a required channel | With `restrictsend`, active transfers close with `You are no longer on a known channel` (`src/iroffer_misc.c:2197`) |
| Parallel downloads | With `ignore_duplicate_ip`, may close and punish with `You are being punished for parallel downloads` |
| Abort | `XDCC CANCEL` closes the transfer. `XDCC REMOVE` leaves the queue. |
| Pack changed on disk | Transfer closes with `Pack file changed` |

**Consequences.**

- The IRC session and channel membership can be required **during** the transfer, not just at request time.
- Duplicate offers are normal, so offer handling must be idempotent.
- Lingering state on the bot can produce `You already requested that pack` on retry.

**Default client timers** are in `ARCHITECTURE.md` §7.7.

## 13. Extensions

| Extension | Form | Evidence | Plan |
|---|---|---|---|
| Turbo | `DCC TSEND`, or `TDCC` tag. Receiver sends no ACKs. | [I5], [X3] notes senders enabling it silently | Parse, refuse by default, later milestone |
| Secure DCC | `DCC SSEND`, `SCHAT`. TLS over DCC with no certificate verification. | [S7, I5]. S7 calls it not widely supported. iroffer-dinoex has SCHAT only in the code read. | Parse, refuse by default, later milestone |
| XMIT | Not a `DCC SEND` variant | Wikipedia only | Out of scope |
| DCC SERVER | mIRC mechanism | Not reviewed | Out of scope |
| SOCKS5 passive | mIRC experimental [V2] | Not reviewed | Out of scope |

## 14. Known gaps

Tracked with priorities in `COMPATIBILITY.md` §5. This specification should not be treated as complete while those remain open.

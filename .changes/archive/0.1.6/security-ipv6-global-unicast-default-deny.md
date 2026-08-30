---
kind: security
summary: isBlockedIPv6 now default-denies any IPv6 address outside 2000::/3 global unicast — including all of 2001::/23 except Teredo — instead of allowing anything not explicitly enumerated
---

`isBlockedIPv6` was deny-known-bad with a default `return false`, so any IPv6
literal outside its enumerated special cases was allowed through — including
non-globally-reachable space such as `100::/64` (RFC 6666 discard-only),
`3fff::/20` (RFC 9637 documentation), `5f00::/16` (RFC 9602 SRv6), `2001:2::/48`
(RFC 5180 benchmarking), the rest of `2001::/23` (IANA "IETF Protocol
Assignments", e.g. `2001:5::1`), and the unallocated majority of the address
space (`4000::/3` through `e000::/3`). It now default-denies anything outside
`2000::/3` (global unicast) and carves out the existing exceptions from there,
rather than enumerating more bad prefixes by hand — including default-blocking
all of `2001::/23` except its one genuinely-handled exception, Teredo
(`2001::/32`), which still classifies by its embedded IPv4 address.

The embedded-IPv4 tunnel/transition forms (IPv4-mapped, IPv4-compatible,
well-known NAT64, 6to4, Teredo) still classify by their embedded IPv4 address,
so a public IPv4 destination tunneled through one of those forms remains
allowed. The one exception is local-use NAT64 (`64:ff9b:1::/48`): RFC 6052
lets its translation prefix length vary (/32 through /96), and RFC 8215 says
applications must not assume where — or whether — an IPv4 address is embedded
in it, so guessing its position (as the previous embedded-IPv4 delegation did)
could both wrongly allow a private destination and wrongly block a public one.
IANA marks the whole `/48` not globally reachable, so it is now blocked
unconditionally instead of decoded.

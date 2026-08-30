# Changelog

## 0.1.6

- Release tooling upgraded to release-kit v0.3.1, so a feature release is graded as a minor rather than a patch
  This package's release-kit was pinned at v0.2.0, whose `stableSemver` incremented the patch component regardless of fragment kind — measured directly, a `minor` and even a `major` bump both resolved to a patch, and `bumpLevelSupport` was absent. Any release adding public surface would therefore have been published as a patch, telling every consumer the upgrade added nothing. That was not hypothetical: during the PKG-114 cuts, alert-kit on v0.2.0 derived 0.5.1 for a release that added a whole new public module, caught only because the derived version was read before cutting.
  
  No runtime change — release-kit is a devDependency and nothing this package exports is affected.
- the aggregate verification gate now rejects stale committed build output
  The package's aggregate verification now checks that the security code shipped
  from `dist/` exactly matches the reviewed TypeScript source.
- isBlockedIPv6 now default-denies any IPv6 address outside 2000::/3 global unicast — including all of 2001::/23 except Teredo — instead of allowing anything not explicitly enumerated
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

## 0.1.5

- Manage releases with release-kit (fragment-based CHANGELOG + version bump)
  Releases are now driven by release-kit: describe each change as a fragment under `.changes/unreleased/` and run `npm run release:cut` to compile them into a new CHANGELOG section, bump the version, and archive the fragments.

## 0.1.4

- **Security — bound the DNS lookup.** `assertSafeUrl` now applies
  `lookupTimeoutMs` (default 5s) to hostname resolution; a hostile or hung
  resolver could previously stall the caller indefinitely. (#6)

## 0.1.3

- Add public contribution, support, and private vulnerability-reporting policies.
- **Security — block private IPv4 destinations encoded through NAT64, 6to4, and
  Teredo IPv6 transition formats.** These forms can otherwise bypass an IPv4
  literal policy while ultimately reaching the same private address.
- **Security documentation — clarify that `assertSafeUrl` is preflight only.**
  It cannot pin a later connection or follow redirects safely by itself; callers
  handling untrusted URLs need a pinned transport and per-hop redirect policy.
- **Developer experience — add `npm run verify`** for the local release gate.
- **Developer security — upgrade Vitest** to a version with no known advisories.

## 0.1.2

Fix — expose `./package.json` in the `exports` map. Without it,
`require('@andrewpopov/url-guard/package.json')` threw
`ERR_PACKAGE_PATH_NOT_EXPORTED` — which broke the standards' own documented way of
verifying an INSTALLED version, the guard against the `github:` re-resolve trap.

No runtime change.

## 0.1.1

**Security fix.** v0.1.0 shipped two gaps in its blocked-range set, so it was not
in fact the superset of the four hand-rolled copies that 0.1.0 claimed to be.
Both were found independently, in two different repos, while diffing the package
against the local guard it was meant to replace — savoro's and smarthome's.

- Block **192.0.2.0/24 (TEST-NET-1)**. 0.1.0 blocked TEST-NET-2 and TEST-NET-3
  but not TEST-NET-1 — an oversight, not a scope decision. savoro's local guard
  covered it (incidentally, via a coarse `192.0.0.0/16` rule).
- Block **fec0::/10 (IPv6 site-local)**. Deprecated by RFC 3879 but still
  routable on legacy networks; smarthome's local guard blocked it explicitly.
  `fe80::/10` link-local was covered; `fec0::/10` is bitwise distinct.

**Adopters on 0.1.0 should upgrade.** cairn and bewks did not regress on
adoption — neither of their originals covered these ranges — but they gain the
coverage here. smarthome carried a local supplemental check to close the gap; it
can now be deleted.

## 0.1.0

Initial release. SSRF guard extracted as a superset of four hand-rolled copies
(cairn, bewks, savoro, smarthome).

- `assertSafeUrl(rawUrl, options)`: rejects non-http(s), credentialed, and
  disallowed-port URLs; `localhost` + internal-suffix hosts; and IP literals or
  DNS resolutions in private/reserved ranges. Returns the parsed `URL`; throws
  `UrlNotAllowedError` (with a `reason`) otherwise.
- Rigorous IPv6 via a byte parser (`ipv6ToBytes`) that expands `::` and dotted
  quads and catches hex IPv4-mapped forms (`::ffff:7f00:1`) the string-matching
  copies missed. Full IPv4 range set incl. CGNAT, TEST-NET-2/3, benchmarking,
  240/4 + broadcast.
- Options: `label`, `allowedProtocols`, `allowedPorts` (bewks), `requireHttps`
  (smarthome), injectable `lookup`.
- Exports the building blocks: `isBlockedIp`, `isBlockedIPv4`, `isBlockedIPv6`,
  `ipv6ToBytes`, `isBlockedHostname`.

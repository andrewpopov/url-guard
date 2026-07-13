# Changelog

## 0.1.3

- **Security — block private IPv4 destinations encoded through NAT64, 6to4, and
  Teredo IPv6 transition formats.** These forms can otherwise bypass an IPv4
  literal policy while ultimately reaching the same private address.
- **Security documentation — clarify that `assertSafeUrl` is preflight only.**
  It cannot pin a later connection or follow redirects safely by itself; callers
  handling untrusted URLs need a pinned transport and per-hop redirect policy.
- **Developer experience — add `npm run verify`** for the local release gate.

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

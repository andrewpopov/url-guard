# Changelog

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

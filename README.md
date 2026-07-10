# @andrewpopov/url-guard

An **SSRF guard** for server-side fetches of user-supplied URLs. One superset of
four hand-rolled copies (cairn, bewks, savoro, smarthome) — so every consumer
gets the strongest version, not whichever one they happened to write.

Blocks:
- non-`http(s)` schemes, embedded credentials, and (optionally) disallowed ports;
- `localhost` and internal-suffix hosts (`.local`, `.internal`, `.home.arpa`, …)
  before any DNS lookup;
- IP-literal hosts, and hostnames that **DNS-resolve**, to private / loopback /
  link-local / CGNAT / metadata / multicast / reserved / TEST-NET ranges — IPv4
  **and** IPv6, including hex IPv4-mapped forms (`::ffff:7f00:1`) that naive
  string-matching guards miss.

Zero runtime dependencies — Node `dns` + `net` (Node ≥ 20).

## Install

```
npm install github:andrewpopov/url-guard#v0.1.0
```

## Use

```ts
import { assertSafeUrl, UrlNotAllowedError } from '@andrewpopov/url-guard';

try {
  const url = await assertSafeUrl(userUrl, { label: 'Webhook URL' });
  // url is a validated URL safe to fetch
} catch (err) {
  if (err instanceof UrlNotAllowedError) {
    // err.reason: 'protocol' | 'credentials' | 'blocked_host' | 'blocked_address' | ...
    throw new BadRequest(err.message);
  }
  throw err;
}
```

It slots straight into `@andrewpopov/webhook-kit` as the injected guard:

```ts
await deliverWebhooks(targets, body, {
  assertSafeUrl: (url) => assertSafeUrl(url, { label: 'Webhook URL' }),
});
```

## Options

| Option | Default | Purpose |
|---|---|---|
| `label` | `"URL"` | Names the URL in error messages. |
| `allowedProtocols` | `['http:','https:']` | Permitted schemes. |
| `allowedPorts` | any | If set, a non-default port must be listed (e.g. `['80','443']`). |
| `requireHttps` | `false` | Reject `http:` (require TLS). |
| `lookup` | `dns.lookup(host,{all,verbatim})` | Injectable resolver for tests. |

## Exports

`assertSafeUrl`, `UrlNotAllowedError`, and the building blocks `isBlockedIp`,
`isBlockedIPv4`, `isBlockedIPv6`, `ipv6ToBytes`, `isBlockedHostname`,
`BLOCKED_HOSTNAMES`, `BLOCKED_HOSTNAME_SUFFIXES`.

## Residual risk (DNS rebinding / TOCTOU)

The hostname is resolved here, but the caller's `fetch` resolves it again — a
rebinding attacker can flip a name public→private between check and fetch. Shrink
the window: check at write time, re-check at fetch time, and use
`redirect: 'manual'`. Fully closing it needs IP pinning (connect to the vetted
IP), which these apps don't warrant. See the note in `src/index.ts`.

## Standards

See [`STANDARDS.md`](./STANDARDS.md) (synced from `agent_brain/knowledge/shared-package-standards.md`).

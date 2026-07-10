import { promises as dns } from 'dns';
import { isIPv4, isIPv6, isIP } from 'net';

/**
 * @andrewpopov/url-guard — SSRF guard for server-side fetches of user-supplied
 * URLs. A single superset of four hand-rolled copies (cairn, bewks, savoro,
 * smarthome): rejects non-http(s), credentialed, and disallowed-port URLs, hosts
 * that are `localhost`/internal-suffix names or IP literals in private/reserved
 * ranges, and hostnames that DNS-resolve to one.
 *
 * Residual, knowingly accepted (DNS rebinding / TOCTOU): the hostname is resolved
 * here but the caller's fetch resolves it again, so a rebinding attacker can flip
 * a name public→private between check and fetch. Shrink the window by (1) checking
 * at write time, (2) re-checking at fetch time, (3) `redirect: 'manual'` on the
 * fetch. Fully closing it needs IP pinning (connect to the vetted IP), which is
 * more than these apps warrant.
 */

export type UrlRejectionReason =
  | 'invalid_url'
  | 'protocol'
  | 'https_required'
  | 'credentials'
  | 'port'
  | 'blocked_host'
  | 'unresolvable'
  | 'blocked_address';

/** Thrown when a URL is not safe to fetch. `reason` lets callers map to their own error. */
export class UrlNotAllowedError extends Error {
  readonly reason: UrlRejectionReason;
  constructor(reason: UrlRejectionReason, message: string) {
    super(message);
    this.name = 'UrlNotAllowedError';
    this.reason = reason;
  }
}

/** Hostnames blocked outright (before any DNS resolution). */
export const BLOCKED_HOSTNAMES: ReadonlySet<string> = new Set(['localhost', 'localhost.localdomain']);

/** Hostname suffixes for internal/mDNS names blocked before resolution. */
export const BLOCKED_HOSTNAME_SUFFIXES: readonly string[] = [
  '.localhost',
  '.local',
  '.internal',
  '.localdomain',
  '.home',
  '.home.arpa',
  '.lan',
];

/** True for an IPv4 literal in a private, loopback, link-local, or reserved range. */
export function isBlockedIPv4(address: string): boolean {
  const parts = address.split('.').map(Number);
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p) || p < 0 || p > 255)) return true;
  const [a, b, c] = parts;

  if (a === 0) return true; // 0.0.0.0/8 "this network"
  if (a === 10) return true; // 10.0.0.0/8 private
  if (a === 127) return true; // 127.0.0.0/8 loopback
  if (a === 100 && b >= 64 && b <= 127) return true; // 100.64.0.0/10 CGNAT
  if (a === 169 && b === 254) return true; // 169.254.0.0/16 link-local incl. 169.254.169.254 metadata
  if (a === 172 && b >= 16 && b <= 31) return true; // 172.16.0.0/12 private
  if (a === 192 && b === 168) return true; // 192.168.0.0/16 private
  if (a === 192 && b === 0 && c === 0) return true; // 192.0.0.0/24 IETF protocol assignments
  if (a === 198 && (b === 18 || b === 19)) return true; // 198.18.0.0/15 benchmarking
  if (a === 198 && b === 51 && c === 100) return true; // 198.51.100.0/24 TEST-NET-2
  if (a === 203 && b === 0 && c === 113) return true; // 203.0.113.0/24 TEST-NET-3
  if (a >= 224 && a <= 239) return true; // 224.0.0.0/4 multicast
  if (a >= 240) return true; // 240.0.0.0/4 reserved/experimental (incl. 255.255.255.255 broadcast)
  return false;
}

/**
 * Parse an IPv6 literal into its 16 bytes, expanding `::` and any trailing
 * dotted-quad (e.g. `::ffff:127.0.0.1`). Returns null if it can't be parsed.
 */
export function ipv6ToBytes(address: string): number[] | null {
  const addr = address.split('%')[0]; // drop zone id (fe80::1%eth0)
  const halves = addr.split('::');
  if (halves.length > 2) return null;

  const expandGroups = (segment: string): number[] | null => {
    if (segment === '') return [];
    const bytes: number[] = [];
    const groups = segment.split(':');
    for (let i = 0; i < groups.length; i += 1) {
      const g = groups[i];
      if (g.includes('.')) {
        // A trailing dotted-quad occupies the final 32 bits (2 hextets).
        if (i !== groups.length - 1) return null;
        const quad = g.split('.').map(Number);
        if (quad.length !== 4 || quad.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return null;
        bytes.push(quad[0], quad[1], quad[2], quad[3]);
        continue;
      }
      if (!/^[0-9a-f]{1,4}$/.test(g)) return null;
      const v = parseInt(g, 16);
      bytes.push((v >> 8) & 0xff, v & 0xff);
    }
    return bytes;
  };

  const head = expandGroups(halves[0]);
  const tail = expandGroups(halves.length === 2 ? halves[1] : '');
  if (head === null || tail === null) return null;

  if (halves.length === 2) {
    const fill = 16 - head.length - tail.length;
    if (fill < 0) return null;
    return [...head, ...new Array(fill).fill(0), ...tail];
  }
  return head.length === 16 ? head : null;
}

/** True for an IPv6 literal in a loopback, unique-local, link-local, multicast, or mapped-private range. */
export function isBlockedIPv6(address: string): boolean {
  const bytes = ipv6ToBytes(address.toLowerCase());
  if (!bytes || bytes.length !== 16) return true; // unparseable — fail closed

  const allZeroThrough = (end: number) => bytes.slice(0, end).every((byte) => byte === 0);

  if (bytes.every((byte) => byte === 0)) return true; // :: unspecified
  if (allZeroThrough(15) && bytes[15] === 1) return true; // ::1 loopback
  if ((bytes[0] & 0xfe) === 0xfc) return true; // fc00::/7 unique-local
  if (bytes[0] === 0xfe && (bytes[1] & 0xc0) === 0x80) return true; // fe80::/10 link-local
  if (bytes[0] === 0xff) return true; // ff00::/8 multicast
  if (bytes[0] === 0x20 && bytes[1] === 0x01 && bytes[2] === 0x0d && bytes[3] === 0xb8) return true; // 2001:db8::/32 documentation

  // IPv4-mapped (::ffff:0:0/96) — dotted or hex form both land here after parsing.
  if (allZeroThrough(10) && bytes[10] === 0xff && bytes[11] === 0xff) {
    return isBlockedIPv4(bytes.slice(12).join('.'));
  }
  // IPv4-compatible (::/96, deprecated) — embedded IPv4 in the low 32 bits.
  if (allZeroThrough(12)) {
    return isBlockedIPv4(bytes.slice(12).join('.'));
  }
  return false;
}

/** True for any IP literal (v4 or v6) in a blocked range. Unrecognized formats fail closed. */
export function isBlockedIp(address: string): boolean {
  if (isIPv4(address)) return isBlockedIPv4(address);
  if (isIPv6(address)) return isBlockedIPv6(address);
  return true;
}

/** True for a hostname blocked before resolution (`localhost`, internal suffixes). */
export function isBlockedHostname(hostname: string): boolean {
  const host = hostname.toLowerCase().replace(/\.$/, '');
  if (BLOCKED_HOSTNAMES.has(host)) return true;
  return BLOCKED_HOSTNAME_SUFFIXES.some((suffix) => host.endsWith(suffix));
}

export interface AssertSafeUrlOptions {
  /** Names the URL in error messages ("Webhook URL", "Image URL", ...). Default "URL". */
  label?: string;
  /** Allowed URL schemes. Default `['http:', 'https:']`. */
  allowedProtocols?: readonly string[];
  /**
   * Allowed explicit ports. When provided, a non-default port must be in this
   * list (an empty/default port is always allowed). Omit to allow any port.
   */
  allowedPorts?: readonly string[];
  /** Reject `http:` (require TLS). Default false. */
  requireHttps?: boolean;
  /** DNS resolver, injectable for tests. Defaults to `dns.lookup(host, { all, verbatim })`. */
  lookup?: (hostname: string) => Promise<Array<{ address: string }>>;
}

async function defaultLookup(hostname: string): Promise<Array<{ address: string }>> {
  return dns.lookup(hostname, { all: true, verbatim: true });
}

/**
 * Assert `rawUrl` is safe to fetch server-side, returning the parsed `URL`.
 * Throws `UrlNotAllowedError` (with a `reason`) otherwise. Blocks non-http(s),
 * credentialed and disallowed-port URLs, `localhost`/internal-suffix hosts, and
 * IP literals or DNS resolutions in private/reserved ranges.
 */
export async function assertSafeUrl(rawUrl: string, options: AssertSafeUrlOptions = {}): Promise<URL> {
  const label = options.label ?? 'URL';
  const protocols = options.allowedProtocols ?? ['http:', 'https:'];

  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new UrlNotAllowedError('invalid_url', `Invalid ${label}`);
  }

  if (!protocols.includes(parsed.protocol)) {
    throw new UrlNotAllowedError('protocol', `${label} must use ${protocols.map((p) => p.replace(':', '')).join(' or ')}`);
  }
  if (options.requireHttps && parsed.protocol === 'http:') {
    throw new UrlNotAllowedError('https_required', `${label} must use https`);
  }
  if (parsed.username || parsed.password) {
    throw new UrlNotAllowedError('credentials', `${label} must not contain credentials`);
  }
  if (options.allowedPorts && parsed.port !== '' && !options.allowedPorts.includes(parsed.port)) {
    throw new UrlNotAllowedError('port', `${label} port is not allowed`);
  }

  // URL.hostname keeps brackets on IPv6 literals ([::1]) — strip them.
  const hostname = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, '');
  if (!hostname) {
    throw new UrlNotAllowedError('blocked_host', `${label} must include a hostname`);
  }
  if (isBlockedHostname(hostname)) {
    throw new UrlNotAllowedError('blocked_host', `${label} may not target an internal host`);
  }

  // IP-literal host — check directly, no DNS round-trip.
  if (isIP(hostname) !== 0) {
    if (isBlockedIp(hostname)) {
      throw new UrlNotAllowedError('blocked_address', `${label} resolves to a disallowed address`);
    }
    return parsed;
  }

  const lookup = options.lookup ?? defaultLookup;
  let addresses: Array<{ address: string }>;
  try {
    addresses = await lookup(hostname);
  } catch {
    throw new UrlNotAllowedError('unresolvable', `${label} host could not be resolved`);
  }
  if (addresses.length === 0) {
    throw new UrlNotAllowedError('unresolvable', `${label} host could not be resolved`);
  }
  if (addresses.some((a) => isBlockedIp(a.address))) {
    throw new UrlNotAllowedError('blocked_address', `${label} resolves to a disallowed address`);
  }
  return parsed;
}

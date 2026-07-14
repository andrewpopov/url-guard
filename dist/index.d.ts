/**
 * @andrewpopov/url-guard — SSRF guard for server-side fetches of user-supplied
 * URLs. A single superset of four hand-rolled copies (cairn, bewks, savoro,
 * smarthome): rejects non-http(s), credentialed, and disallowed-port URLs, hosts
 * that are `localhost`/internal-suffix names or IP literals in private/reserved
 * ranges, and hostnames that DNS-resolve to one.
 *
 * This is a preflight guard, not a complete SSRF transport boundary. The hostname
 * is resolved here but a caller's fetch resolves it again, so a rebinding attacker
 * can flip a name public→private between check and connection. Use a transport
 * that pins the vetted address and revalidates every redirect for untrusted URLs.
 */
export type UrlRejectionReason = 'invalid_url' | 'protocol' | 'https_required' | 'credentials' | 'port' | 'blocked_host' | 'unresolvable' | 'blocked_address';
/** Thrown when a URL is not safe to fetch. `reason` lets callers map to their own error. */
export declare class UrlNotAllowedError extends Error {
    readonly reason: UrlRejectionReason;
    constructor(reason: UrlRejectionReason, message: string);
}
/** Hostnames blocked outright (before any DNS resolution). */
export declare const BLOCKED_HOSTNAMES: ReadonlySet<string>;
/** Hostname suffixes for internal/mDNS names blocked before resolution. */
export declare const BLOCKED_HOSTNAME_SUFFIXES: readonly string[];
/** True for an IPv4 literal in a private, loopback, link-local, or reserved range. */
export declare function isBlockedIPv4(address: string): boolean;
/**
 * Parse an IPv6 literal into its 16 bytes, expanding `::` and any trailing
 * dotted-quad (e.g. `::ffff:127.0.0.1`). Returns null if it can't be parsed.
 */
export declare function ipv6ToBytes(address: string): number[] | null;
/** True for an IPv6 literal in a loopback, unique-local, link-local, multicast, or mapped-private range. */
export declare function isBlockedIPv6(address: string): boolean;
/** True for any IP literal (v4 or v6) in a blocked range. Unrecognized formats fail closed. */
export declare function isBlockedIp(address: string): boolean;
/** True for a hostname blocked before resolution (`localhost`, internal suffixes). */
export declare function isBlockedHostname(hostname: string): boolean;
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
    lookup?: (hostname: string) => Promise<Array<{
        address: string;
    }>>;
    /**
     * Upper bound, in milliseconds, on how long the DNS lookup (default or
     * caller-injected `lookup`) may take before the URL is rejected with reason
     * `unresolvable`. Applies uniformly so a hostile or slow resolver cannot hang
     * the caller indefinitely. Default `5000`. Pass `0` or `Infinity` to disable
     * the bound entirely (e.g. a caller that already enforces its own timeout).
     */
    lookupTimeoutMs?: number;
}
/**
 * Assert `rawUrl` is safe to fetch server-side, returning the parsed `URL`.
 * Throws `UrlNotAllowedError` (with a `reason`) otherwise. Blocks non-http(s),
 * credentialed and disallowed-port URLs, `localhost`/internal-suffix hosts, and
 * IP literals or DNS resolutions in private/reserved ranges.
 */
export declare function assertSafeUrl(rawUrl: string, options?: AssertSafeUrlOptions): Promise<URL>;

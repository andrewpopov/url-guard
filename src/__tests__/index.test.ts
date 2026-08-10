import { describe, it, expect, vi } from 'vitest';
import {
  assertSafeUrl,
  isBlockedIp,
  isBlockedIPv4,
  isBlockedIPv6,
  ipv6ToBytes,
  isBlockedHostname,
  UrlNotAllowedError,
} from '../index';

// A lookup stub so DNS-path tests never touch the network.
const resolvesTo = (...addresses: string[]) => async () => addresses.map((address) => ({ address }));
const resolvesEmpty = async () => [];
const resolveThrows = async () => {
  throw new Error('ENOTFOUND');
};

describe('isBlockedIPv4 — every range', () => {
  it.each([
    ['0.0.0.0', true],
    ['10.1.2.3', true],
    ['127.0.0.1', true],
    ['100.64.0.1', true], // CGNAT
    ['100.127.255.255', true],
    ['169.254.169.254', true], // cloud metadata
    ['172.16.0.1', true],
    ['172.31.255.255', true],
    ['192.168.1.1', true],
    ['192.0.0.1', true], // IETF protocol
    ['192.0.2.1', true], // TEST-NET-1 (savoro) — regression: shipped unblocked in v0.1.0
    ['192.0.2.255', true],
    ['192.88.99.1', true], // deprecated 6to4 relay anycast
    ['198.18.0.1', true], // benchmarking
    ['198.51.100.4', true], // TEST-NET-2 (savoro)
    ['203.0.113.4', true], // TEST-NET-3 (savoro)
    ['224.0.0.1', true], // multicast
    ['240.0.0.1', true], // reserved (cairn)
    ['255.255.255.255', true], // broadcast
    ['8.8.8.8', false],
    ['1.1.1.1', false],
    ['172.15.0.1', false], // just outside 172.16/12
    ['172.32.0.1', false],
    ['100.63.0.1', false], // just outside CGNAT
  ])('%s -> blocked=%s', (ip, blocked) => {
    expect(isBlockedIPv4(ip)).toBe(blocked);
  });

  it('fails closed on malformed input', () => {
    expect(isBlockedIPv4('999.1.1.1')).toBe(true);
    expect(isBlockedIPv4('1.2.3')).toBe(true);
  });
});

describe('isBlockedIPv6 — incl. forms string-matchers miss', () => {
  it.each([
    ['::1', true], // loopback
    ['::', true], // unspecified
    ['fc00::1', true], // unique-local
    ['fd12:3456::1', true],
    ['fe80::1', true], // link-local
    ['fec0::1', true], // site-local, deprecated by RFC 3879 (smarthome) — regression: shipped unblocked in v0.1.0
    ['feff:ffff::1', true], // top of fec0::/10
    ['ff02::1', true], // multicast
    ['2001:db8::1', true], // documentation
    ['::ffff:127.0.0.1', true], // IPv4-mapped, dotted
    ['::ffff:7f00:1', true], // IPv4-mapped, HEX form — string-matchers miss this
    ['::ffff:a9fe:a9fe', true], // 169.254.169.254 as hex-mapped
    ['::7f00:1', true], // IPv4-compatible (deprecated)
    ['64:ff9b::a00:1', true], // well-known NAT64 carrying 10.0.0.1
    ['64:ff9b::808:808', false], // well-known NAT64 carrying public 8.8.8.8
    ['64:ff9b:1::a00:1', true], // local-use NAT64 carrying 10.0.0.1
    ['2002:a00:1::', true], // 6to4 carrying 10.0.0.1
    ['2002:808:808::', false], // 6to4 carrying public 8.8.8.8
    ['2001:0:0:0:0:0:f5ff:fffe', true], // Teredo-obfuscated 10.0.0.1
    ['2001:0:4137:9e76:8000:b23a:fefe:fefe', false], // Teredo, real server field (65.55.158.118), obfuscated public 1.1.1.1
    ['2606:4700:4700::1111', false], // public (Cloudflare DNS)
    ['2001:4860:4860::8888', false], // public (Google DNS)
  ])('%s -> blocked=%s', (ip, blocked) => {
    expect(isBlockedIPv6(ip)).toBe(blocked);
  });

  it('fails closed on unparseable IPv6', () => {
    expect(isBlockedIPv6('not:an:address')).toBe(true);
    expect(isBlockedIPv6('gggg::1')).toBe(true);
  });

  // PKG-138: isBlockedIPv6 was deny-known-bad with a default `return false`,
  // so anything outside the enumerated special cases — including
  // non-globally-reachable space like 100::/64 discard-only, 3fff::/20
  // documentation, 5f00::/16 SRv6, and the unallocated majority of the
  // address space — was allowed through. Global unicast is 2000::/3; the fix
  // default-denies everything outside it instead of enumerating more bad
  // prefixes one at a time.
  describe('default-deny outside 2000::/3 global unicast (PKG-138)', () => {
    it.each([
      ['100::1', true], // 100::/64 discard-only (RFC 6666)
      ['3fff::1', true], // 3fff::/20 documentation (RFC 9637)
      ['5f00::1', true], // 5f00::/16 SRv6 (RFC 9602)
      ['4000::1', true], // unallocated
      ['8000::1', true], // unallocated
      ['c000::1', true], // unallocated
      ['e000::1', true], // unallocated
      ['2001:2::1', true], // 2001:2::/48 benchmarking (RFC 5180)
      ['2606:4700:4700::1111', false], // real global unicast (Cloudflare) — must not regress to blocked
      ['2a00:1450:4001::1', false], // real global unicast (Google) — must not regress to blocked
    ])('%s -> blocked=%s', (ip, blocked) => {
      expect(isBlockedIPv6(ip)).toBe(blocked);
    });

    it('still blocks every previously-covered range (loopback, ULA, link-local, multicast, doc)', () => {
      expect(isBlockedIPv6('::1')).toBe(true);
      expect(isBlockedIPv6('fc00::1')).toBe(true);
      expect(isBlockedIPv6('fe80::1')).toBe(true);
      expect(isBlockedIPv6('ff00::1')).toBe(true);
      expect(isBlockedIPv6('2001:db8::1')).toBe(true);
    });

    // NOTE: these "both directions" checks pass against the pre-PKG-138 code
    // too (they exercise carve-outs that already existed) — they are
    // regression guards for the transition forms, not canary proof of this
    // fix. The canary evidence for this fix is the it.each table above.
    it('still classifies embedded-IPv4 tunnel forms by the embedded address, both directions', () => {
      // NAT64 (well-known 64:ff9b::/96), dotted-decimal embedded form.
      expect(isBlockedIPv6('64:ff9b::192.168.0.1')).toBe(true);
      expect(isBlockedIPv6('64:ff9b::8.8.8.8')).toBe(false);
      // 6to4 (2002::/16).
      expect(isBlockedIPv6('2002:a00:1::')).toBe(true); // embeds 10.0.0.1
      expect(isBlockedIPv6('2002:808:808::')).toBe(false); // embeds 8.8.8.8
      // Teredo (2001:0000::/32).
      expect(isBlockedIPv6('2001:0:0:0:0:0:f5ff:fffe')).toBe(true); // embeds 10.0.0.1
      expect(isBlockedIPv6('2001:0:4137:9e76:8000:b23a:fefe:fefe')).toBe(false); // real server field, embeds 1.1.1.1
    });
  });

  // PKG-138 follow-up (Codex review): the first pass left two default-allow
  // gaps in the same class the ticket exists to close.
  describe('2001::/23 default-block and local-use NAT64 unconditional block (PKG-138 follow-up)', () => {
    it.each([
      // Hole 1: 2001::/23 (IANA "IETF Protocol Assignments") is inside
      // 2000::/3 and has no more-specific carve-out for these — they must not
      // fall through to the final `return false`.
      ['2001:5::1', true],
      ['2001:6::1', true],
      ['2001:20::1', true], // another unallocated address within the /23
      // Teredo (2001::/32) is the one genuinely-handled exception within the
      // /23 and must keep classifying by its embedded IPv4 address.
      ['2001:0:0:0:0:0:f5ff:fffe', true], // private embedded (10.0.0.1) — still blocked
      ['2001:0:4137:9e76:8000:b23a:fefe:fefe', false], // public embedded (1.1.1.1) — still allowed
      // Hole 2: local-use NAT64 (64:ff9b:1::/48) has no fixed embedded-IPv4
      // position (RFC 6052/8215), so it must block unconditionally —
      // regardless of what the trailing bits look like.
      ['64:ff9b:1:1:a:0:100:0', true], // would read as public 1.0.0.0 if (wrongly) decoded from the last 32 bits
      ['64:ff9b:1:1:8:808:7f00:0', true], // would read as blocked 127.0.0.0 if (wrongly) decoded from the last 32 bits
      // Well-known NAT64 (64:ff9b::/96) is unchanged in both directions.
      ['64:ff9b::a00:1', true],
      ['64:ff9b::808:808', false],
    ])('%s -> blocked=%s', (ip, blocked) => {
      expect(isBlockedIPv6(ip)).toBe(blocked);
    });
  });
});

describe('ipv6ToBytes', () => {
  it('expands :: and dotted-quad tails', () => {
    expect(ipv6ToBytes('::1')?.slice(-1)).toEqual([1]);
    expect(ipv6ToBytes('::ffff:1.2.3.4')?.slice(-6)).toEqual([0xff, 0xff, 1, 2, 3, 4]);
    expect(ipv6ToBytes('fe80::1')?.slice(0, 2)).toEqual([0xfe, 0x80]);
  });
  it('returns null on garbage', () => {
    expect(ipv6ToBytes('1::2::3')).toBeNull();
    expect(ipv6ToBytes('xyz')).toBeNull();
  });
});

describe('isBlockedIp dispatch', () => {
  it('fails closed on a non-IP string', () => {
    expect(isBlockedIp('example.com')).toBe(true);
    expect(isBlockedIp('8.8.8.8')).toBe(false);
    expect(isBlockedIp('2606:4700:4700::1111')).toBe(false);
  });
});

describe('isBlockedHostname', () => {
  it.each([
    ['localhost', true],
    ['localhost.localdomain', true],
    ['printer.local', true],
    ['db.internal', true],
    ['gw.home.arpa', true],
    ['nas.lan', true],
    ['x.home', true],
    ['foo.localhost', true],
    ['example.com', false],
    ['api.github.com', false],
    ['LOCALHOST', true], // case-insensitive
    ['printer.local.', true], // trailing dot
  ])('%s -> blocked=%s', (host, blocked) => {
    expect(isBlockedHostname(host)).toBe(blocked);
  });
});

describe('assertSafeUrl', () => {
  const opts = { lookup: resolvesTo('8.8.8.8') };

  it('accepts a public https URL and returns the parsed URL', async () => {
    const url = await assertSafeUrl('https://example.com/hook', opts);
    expect(url).toBeInstanceOf(URL);
    expect(url.hostname).toBe('example.com');
  });

  it('rejects non-http(s) protocols', async () => {
    await expect(assertSafeUrl('ftp://example.com', opts)).rejects.toMatchObject({ reason: 'protocol' });
    await expect(assertSafeUrl('file:///etc/passwd', opts)).rejects.toBeInstanceOf(UrlNotAllowedError);
  });

  it('rejects credentials in the URL', async () => {
    await expect(assertSafeUrl('https://user:pass@example.com', opts)).rejects.toMatchObject({ reason: 'credentials' });
  });

  it('rejects an unparseable URL', async () => {
    await expect(assertSafeUrl('not a url', opts)).rejects.toMatchObject({ reason: 'invalid_url' });
  });

  it('rejects localhost and internal-suffix hosts before any DNS lookup', async () => {
    const boom = { lookup: resolveThrows }; // proves no DNS is consulted
    await expect(assertSafeUrl('http://localhost:3000/x', boom)).rejects.toMatchObject({ reason: 'blocked_host' });
    await expect(assertSafeUrl('http://printer.local/x', boom)).rejects.toMatchObject({ reason: 'blocked_host' });
  });

  it('blocks IP-literal hosts in private ranges without DNS', async () => {
    const boom = { lookup: resolveThrows };
    await expect(assertSafeUrl('http://169.254.169.254/latest/meta-data', boom)).rejects.toMatchObject({ reason: 'blocked_address' });
    await expect(assertSafeUrl('http://[::1]:8080/x', boom)).rejects.toMatchObject({ reason: 'blocked_address' });
    await expect(assertSafeUrl('http://[::ffff:7f00:1]/x', boom)).rejects.toMatchObject({ reason: 'blocked_address' });
  });

  it('accepts a public IP literal', async () => {
    await expect(assertSafeUrl('https://8.8.8.8/x', { lookup: resolveThrows })).resolves.toBeInstanceOf(URL);
  });

  it('blocks a hostname that DNS-resolves to a private address', async () => {
    await expect(assertSafeUrl('https://evil.example.com', { lookup: resolvesTo('10.0.0.5') })).rejects.toMatchObject({
      reason: 'blocked_address',
    });
  });

  it('blocks when ANY resolved address is private (dual-stack)', async () => {
    await expect(
      assertSafeUrl('https://mixed.example.com', { lookup: resolvesTo('8.8.8.8', '127.0.0.1') }),
    ).rejects.toMatchObject({ reason: 'blocked_address' });
  });

  it('rejects an unresolvable or empty-resolution host', async () => {
    await expect(assertSafeUrl('https://nope.example.com', { lookup: resolveThrows })).rejects.toMatchObject({ reason: 'unresolvable' });
    await expect(assertSafeUrl('https://empty.example.com', { lookup: resolvesEmpty })).rejects.toMatchObject({ reason: 'unresolvable' });
  });

  it('honors allowedPorts when provided (bewks policy)', async () => {
    await expect(assertSafeUrl('https://example.com:8443/x', { ...opts, allowedPorts: ['80', '443'] })).rejects.toMatchObject({
      reason: 'port',
    });
    await expect(assertSafeUrl('https://example.com/x', { ...opts, allowedPorts: ['80', '443'] })).resolves.toBeInstanceOf(URL);
    // Omitting allowedPorts allows any port.
    await expect(assertSafeUrl('https://example.com:8443/x', opts)).resolves.toBeInstanceOf(URL);
  });

  it('honors requireHttps (smarthome policy)', async () => {
    await expect(assertSafeUrl('http://example.com/x', { ...opts, requireHttps: true })).rejects.toMatchObject({
      reason: 'https_required',
    });
    await expect(assertSafeUrl('https://example.com/x', { ...opts, requireHttps: true })).resolves.toBeInstanceOf(URL);
  });

  it('uses the label in error messages', async () => {
    await expect(assertSafeUrl('ftp://example.com', { ...opts, label: 'Webhook URL' })).rejects.toThrow(/Webhook URL/);
  });
});

describe('assertSafeUrl — lookupTimeoutMs', () => {
  const neverSettles = () => new Promise<Array<{ address: string }>>(() => {});

  it('times out a hung lookup and maps it to reason "unresolvable", promptly', async () => {
    const start = Date.now();
    await expect(
      assertSafeUrl('https://hangs.example.com', { lookup: neverSettles, lookupTimeoutMs: 20 }),
    ).rejects.toMatchObject({ reason: 'unresolvable' });
    // Generous upper bound so this stays reliable under CI load, but tight
    // enough to prove the 20ms bound actually fired rather than some other
    // (much larger) fallback.
    expect(Date.now() - start).toBeLessThan(2000);
  });

  it('does not affect a lookup that settles well within the timeout', async () => {
    const url = await assertSafeUrl('https://fast.example.com', {
      lookup: resolvesTo('8.8.8.8'),
      lookupTimeoutMs: 20,
    });
    expect(url).toBeInstanceOf(URL);
  });

  it('lookupTimeoutMs: 0 disables the bound entirely', async () => {
    // A lookup that resolves after the "disabled" window would still time out
    // if the 0 sentinel were mishandled as "immediate timeout" instead of
    // "no timeout".
    const slowButFinite = () =>
      new Promise<Array<{ address: string }>>((resolve) => setTimeout(() => resolve([{ address: '8.8.8.8' }]), 30));
    await expect(
      assertSafeUrl('https://slow.example.com', { lookup: slowButFinite, lookupTimeoutMs: 0 }),
    ).resolves.toBeInstanceOf(URL);
  });

  it('leaves no dangling timer once a fast lookup settles (finally-clears the timer)', async () => {
    const setTimeoutSpy = vi.spyOn(global, 'setTimeout');
    const clearTimeoutSpy = vi.spyOn(global, 'clearTimeout');

    await assertSafeUrl('https://fast.example.com', { lookup: resolvesTo('8.8.8.8'), lookupTimeoutMs: 5000 });

    expect(setTimeoutSpy).toHaveBeenCalledTimes(1);
    expect(clearTimeoutSpy).toHaveBeenCalledTimes(1);
    // The exact timer id returned by our setTimeout call must be the one cleared.
    expect(clearTimeoutSpy.mock.calls[0][0]).toBe(setTimeoutSpy.mock.results[0].value);

    setTimeoutSpy.mockRestore();
    clearTimeoutSpy.mockRestore();
  });
});

describe('assertSafeUrl — defaultLookup (real dns.lookup, no injected lookup)', () => {
  // '.invalid' is reserved by RFC 2606 and is guaranteed to never resolve, so
  // this exercises the real dns.lookup() path deterministically and offline
  // (an ENOTFOUND-style resolver error, not a network round-trip to a real
  // authoritative server).
  it('rejects a hostname under the reserved .invalid TLD with reason "unresolvable"', async () => {
    await expect(assertSafeUrl('https://this-host-does-not-exist.invalid/x')).rejects.toMatchObject({
      reason: 'unresolvable',
    });
  }, 10000);
});

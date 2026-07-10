import { describe, it, expect } from 'vitest';
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
    ['ff02::1', true], // multicast
    ['2001:db8::1', true], // documentation
    ['::ffff:127.0.0.1', true], // IPv4-mapped, dotted
    ['::ffff:7f00:1', true], // IPv4-mapped, HEX form — string-matchers miss this
    ['::ffff:a9fe:a9fe', true], // 169.254.169.254 as hex-mapped
    ['::7f00:1', true], // IPv4-compatible (deprecated)
    ['2606:4700:4700::1111', false], // public (Cloudflare DNS)
    ['2001:4860:4860::8888', false], // public (Google DNS)
  ])('%s -> blocked=%s', (ip, blocked) => {
    expect(isBlockedIPv6(ip)).toBe(blocked);
  });

  it('fails closed on unparseable IPv6', () => {
    expect(isBlockedIPv6('not:an:address')).toBe(true);
    expect(isBlockedIPv6('gggg::1')).toBe(true);
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

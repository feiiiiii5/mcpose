import { describe, it, expect, beforeAll } from 'vitest';
import { createProxyContext } from 'mcpose';
import type { Identity } from 'mcpose';
import { createAuditMiddleware } from '../middleware.js';
import { createSensitivityResolver } from '../sensitivity.js';
import { createDefaultSigningKeyProvider } from '../signingKey.js';
import type { AuditEvent, ReplayManifest } from '../types.js';
import { verifyAuditChain, verifyManifestSignature } from '../verify.js';

// The stored `signature` and `chainHash` are exact canonical hex strings.
// Buffer.from(x, 'hex') is lenient, though: it drops a trailing nibble on
// odd-length input and stops at the first non-hex character, so a stored
// string with either appended decodes to the real bytes and used to verify.
// verifyMerkleProof compares its hex strings exactly, so the keyed verifiers
// must agree.

const identity: Identity = {
  sub: 'user-1',
  type: 'human',
  roles: ['analyst'],
  claims: {},
  resolvedAt: '2026-06-01T00:00:00.000Z',
  source: 'jwt',
};

describe('strict hex comparison in the keyed verifiers', () => {
  let events: AuditEvent[];
  let manifest: ReplayManifest;
  let signingKey: ReturnType<typeof createDefaultSigningKeyProvider>;

  beforeAll(async () => {
    events = [];
    signingKey = createDefaultSigningKeyProvider('test-secret');
    const { middleware, closeSession } = createAuditMiddleware({
      signingKey,
      sensitivityResolver: createSensitivityResolver({ search: 'low' }),
      onEvent: (e) => {
        events.push(e);
      },
    });
    await middleware(
      {
        method: 'tools/call' as const,
        params: { name: 'search', arguments: {} },
      },
      async () => ({ content: [] }),
      createProxyContext({
        transport: 'http',
        identity,
        sessionId: 'strict-hex',
        proxy: { name: 'test-proxy', version: '0.0.0' },
      }),
    );
    manifest = (await closeSession('strict-hex'))!;
  });

  it('accepts the untampered chain and manifest', async () => {
    expect(await verifyAuditChain(events, signingKey)).toEqual({ valid: true });
    expect(await verifyManifestSignature(manifest, signingKey)).toBe(true);
  });

  it.each(['0', 'z', 'zz'])(
    'rejects a signature with %s appended',
    async (suffix) => {
      const result = await verifyManifestSignature(
        { ...manifest, signature: manifest.signature + suffix },
        signingKey,
      );
      expect(result).toBe(false);
    },
  );

  it('rejects an uppercase spelling of the true signature', async () => {
    const uppercase = manifest.signature.toUpperCase();
    expect(uppercase).not.toBe(manifest.signature);
    const result = await verifyManifestSignature(
      { ...manifest, signature: uppercase },
      signingKey,
    );
    expect(result).toBe(false);
  });

  it.each(['0', 'z', 'zz'])(
    'rejects a chainHash with %s appended',
    async (suffix) => {
      const changed = events.map((e, i) =>
        i === 0 ? { ...e, chainHash: e.chainHash + suffix } : e,
      );
      expect(await verifyAuditChain(changed, signingKey)).toEqual({
        valid: false,
        index: 0,
        reason: 'chainHash mismatch',
      });
    },
  );

  it('rejects an uppercase spelling of the true chainHash', async () => {
    const changed = events.map((e, i) =>
      i === 0 ? { ...e, chainHash: e.chainHash.toUpperCase() } : e,
    );
    expect(changed[0]!.chainHash).not.toBe(events[0]!.chainHash);
    expect(await verifyAuditChain(changed, signingKey)).toEqual({
      valid: false,
      index: 0,
      reason: 'chainHash mismatch',
    });
  });
});

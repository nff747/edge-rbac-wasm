import { RbacUser } from './types.js';
import { jwtVerify } from 'jose';

export interface JwtClaims {
  sub: string;
  tenant_id?: number;
  roles?: number[];
  exp?: number;
  nbf?: number;
  [key: string]: any;
}

export interface JwtValidationOptions {
  clockSkewSeconds?: number;
  checkNbf?: boolean;
}

/** Must cryptographically verify the token, issuer and audience before returning claims. */
export type VerifiedTokenProvider = (token: string) => Promise<JwtClaims>;

/** Verify with an application-provided trusted key; never use a key supplied by the token. */
export function createJwtVerifier(config: { key: CryptoKey | Uint8Array; issuer: string; audience: string; algorithms: string[] }): VerifiedTokenProvider {
  if (!config.key || !config.issuer || !config.audience || !config.algorithms?.length || config.algorithms.some(a => !a || a.toLowerCase() === 'none')) {
    throw new Error('Trusted key, issuer, audience and allowed algorithms are required');
  }
  return async token => {
    const { payload } = await jwtVerify(token, config.key, {
      issuer: config.issuer, audience: config.audience, algorithms: config.algorithms,
      requiredClaims: ['sub', 'exp', 'tenant_id', 'roles']
    });
    const claims = payload as unknown as JwtClaims;
    EdgeJwtParser.fromVerifiedClaims(claims);
    return claims;
  };
}

export class EdgeJwtParser {
  /** Diagnostic parsing only. The result is untrusted and must never authorize a request. */
  public static decodeUnverified(token: string): JwtClaims {
    const parts = token.split('.');
    if (parts.length !== 3) {
      throw new Error('Invalid JWT format');
    }

    const payload = parts[1];
    // Base64Url decode in Edge / Node
    const base64 = payload.replace(/-/g, '+').replace(/_/g, '/');
    const jsonStr = Buffer.from(base64, 'base64').toString('utf-8');
    return JSON.parse(jsonStr);
  }

  /** Map claims already verified by a trusted identity provider. Never pass decoded-only claims. */
  public static fromVerifiedClaims(claims: JwtClaims, options: JwtValidationOptions = {}): RbacUser {
    const clockSkew = options.clockSkewSeconds ?? 0;
    const nowSec = Date.now() / 1000;

    if (!claims || typeof claims.sub !== 'string' || !claims.sub.trim() || !Number.isFinite(claims.exp)) throw new Error('Invalid verified claims');
    if (!Number.isSafeInteger(claims.tenant_id) || claims.tenant_id! < 1 || !Array.isArray(claims.roles) || !claims.roles.length || claims.roles.some(role => !Number.isSafeInteger(role) || role < 1 || role > 0xffffffff)) throw new Error('Invalid verified authorization claims');
    if (claims.nbf !== undefined && (!Number.isFinite(claims.nbf) || claims.nbf - clockSkew > nowSec)) throw new Error('Token is not yet valid');

    if (claims.exp !== undefined && claims.exp + clockSkew <= nowSec) {
      throw new Error('Token has expired');
    }

    return {
      id: claims.sub,
      tenantId: claims.tenant_id!,
      roles: claims.roles!,
      attributes: {
        email: claims.email || '',
        sub: claims.sub
      }
    };
  }
}

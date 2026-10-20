import { RbacUser } from './types';

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

export class EdgeJwtParser {
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

  public static toRbacUser(token: string, options: JwtValidationOptions = {}): RbacUser {
    const claims = this.decodeUnverified(token);
    const clockSkew = options.clockSkewSeconds ?? 0;
    const nowSec = Date.now() / 1000;

    if (claims.exp !== undefined && claims.exp + clockSkew < nowSec) {
      throw new Error('Token has expired');
    }

    if (options.checkNbf && claims.nbf !== undefined && claims.nbf - clockSkew > nowSec) {
      throw new Error('Token is not yet valid');
    }

    return {
      id: claims.sub,
      tenantId: claims.tenant_id ?? 1,
      roles: claims.roles ?? [1], // Default viewer
      attributes: {
        email: claims.email || '',
        sub: claims.sub
      }
    };
  }
}

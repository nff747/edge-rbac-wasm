import { RbacUser } from './types';

export interface JwtClaims {
  sub: string;
  tenant_id?: number;
  roles?: number[];
  exp?: number;
  [key: string]: any;
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

  public static toRbacUser(token: string): RbacUser {
    const claims = this.decodeUnverified(token);

    if (claims.exp && claims.exp * 1000 < Date.now()) {
      throw new Error('Token has expired');
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

import { randomBytes } from 'node:crypto';
import { SignJWT } from 'jose';
import { describe, it, expect } from 'vitest';
import { createJwtVerifier } from '../src/jwt';
import { createCloudflareRbacMiddleware } from '../src/cloudflare';
import { EdgeRbacClient } from '../src/client';

describe('real signed JWT verification', () => {
  const key = randomBytes(32), otherKey = randomBytes(32);
  const verify = createJwtVerifier({key,issuer:'https://issuer.example',audience:'lunar-api',algorithms:['HS256']});
  const sign = (k = key, issuer = 'https://issuer.example', audience = 'lunar-api', expiry = '5m') =>
    new SignJWT({tenant_id:1,roles:[3]}).setProtectedHeader({alg:'HS256'}).setSubject('test-user').setIssuer(issuer).setAudience(audience).setExpirationTime(expiry).sign(k);
  it('accepts only a correctly signed token from the configured issuer and audience', async () => {
    expect((await verify(await sign())).sub).toBe('test-user');
    await expect(verify(await sign(otherKey))).rejects.toThrow();
    await expect(verify(await sign(key,'https://other.example'))).rejects.toThrow();
    await expect(verify(await sign(key,'https://issuer.example','other-audience'))).rejects.toThrow();
    await expect(verify(await sign(key,'https://issuer.example','lunar-api','-5m'))).rejects.toThrow();
  });
  it('rejects a forged administrator token through middleware', async () => {
    const client = new EdgeRbacClient({policyEngine:{canAccess:()=>true}});
    const middleware = createCloudflareRbacMiddleware(client, verify);
    const token = await sign(otherKey);
    const response = await middleware(new Request('https://app.example/',{headers:{authorization:`Bearer ${token}`}}),'admin','private',1);
    expect(response?.status).toBe(401);
  });
  it('rejects missing trust configuration', () => {
    expect(() => createJwtVerifier({key,issuer:'',audience:'lunar-api',algorithms:['HS256']})).toThrow();
    expect(() => createJwtVerifier({key,issuer:'issuer',audience:'lunar-api',algorithms:['none']})).toThrow();
  });
});

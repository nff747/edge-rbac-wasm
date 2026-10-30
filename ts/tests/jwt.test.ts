import { describe, it, expect } from 'vitest';
import { EdgeJwtParser } from '../src/jwt';
describe('verified claim mapping', () => {
  const claims = () => ({ sub:'user_456', tenant_id:101, roles:[2], exp:Math.floor(Date.now()/1000)+3600 });
  it('maps explicit verified authorization claims', () => expect(EdgeJwtParser.fromVerifiedClaims(claims())).toMatchObject({id:'user_456',tenantId:101,roles:[2]}));
  it('rejects missing or malformed claims', () => {
    for (const invalid of [{...claims(),sub:''},{...claims(),tenant_id:0},{...claims(),roles:[]},{...claims(),exp:NaN}]) expect(() => EdgeJwtParser.fromVerifiedClaims(invalid)).toThrow();
  });
  it('rejects expired and not-yet-valid claims', () => {
    expect(() => EdgeJwtParser.fromVerifiedClaims({...claims(),exp:Math.floor(Date.now()/1000)-1})).toThrow('expired');
    expect(() => EdgeJwtParser.fromVerifiedClaims({...claims(),nbf:Math.floor(Date.now()/1000)+120})).toThrow('not yet valid');
  });
});

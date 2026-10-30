import { describe, it, expect } from 'vitest';
import { EdgeRbacClient } from '../src/client';
import { RbacUser } from '../src/types';

describe('EdgeRbacClient', () => {
  const client = new EdgeRbacClient({policyEngine:{canAccess:(roles, _resource, permission) => roles.some(role => role === 3 || permission === 1 || role === 2 && permission === 2)}});

  const viewerUser: RbacUser = {
    id: 'user_1',
    tenantId: 100,
    roles: [1]
  };

  const editorUser: RbacUser = {
    id: 'user_2',
    tenantId: 100,
    roles: [2]
  };

  it('verifies permissions for standard roles', async () => {
    expect(await client.can(viewerUser, 'read', 'api:docs', 100)).toBe(true);
    expect(await client.can(viewerUser, 'write', 'api:docs', 100)).toBe(false);

    expect(await client.can(editorUser, 'read', 'api:docs', 100)).toBe(true);
    expect(await client.can(editorUser, 'write', 'api:docs', 100)).toBe(true);
  });

  it('enforces tenant boundary isolation', async () => {
    // Editor in tenant 100 cannot access tenant 200
    const decision = await client.authorize(editorUser, 'read', 'api:docs', 200);
    expect(decision.granted).toBe(false);
    expect(decision.reason).toContain('Cross-tenant boundary violation');
  });
  it('fails closed without a configured engine and across tenants for admins', async () => {
    await expect(new EdgeRbacClient().can(viewerUser, 'read', 'api:docs', 100)).rejects.toThrow('No authorization policy engine');
    await expect(client.can(viewerUser, 'read', 'api:docs', undefined as any)).rejects.toThrow('resource tenant');
    expect((await client.authorize({...editorUser, roles:[3]}, 'read', 'api:docs', 200)).granted).toBe(false);
  });
});

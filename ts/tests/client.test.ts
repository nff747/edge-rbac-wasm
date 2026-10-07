import { describe, it, expect } from 'vitest';
import { EdgeRbacClient } from '../src/client';
import { RbacUser } from '../src/types';

describe('EdgeRbacClient', () => {
  const client = new EdgeRbacClient();

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
    expect(await client.can(viewerUser, 'read', 'api:docs')).toBe(true);
    expect(await client.can(viewerUser, 'write', 'api:docs')).toBe(false);

    expect(await client.can(editorUser, 'read', 'api:docs')).toBe(true);
    expect(await client.can(editorUser, 'write', 'api:docs')).toBe(true);
  });

  it('enforces tenant boundary isolation', async () => {
    // Editor in tenant 100 cannot access tenant 200
    const decision = await client.authorize(editorUser, 'read', 'api:docs', 200);
    expect(decision.granted).toBe(false);
    expect(decision.reason).toContain('Cross-tenant boundary violation');
  });
});

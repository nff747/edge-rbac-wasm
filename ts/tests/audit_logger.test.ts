import { describe, it, expect, vi } from 'vitest';
import { EdgeAuditLogger } from '../src/audit_logger';

describe('EdgeAuditLogger', () => {
  it('buffers audit entries and flushes when batch limit is reached', () => {
    const onFlush = vi.fn();
    const logger = new EdgeAuditLogger(3, onFlush);

    logger.log({
      timestamp: Date.now(),
      requestId: 'req_1',
      tenantId: 1,
      roleId: 2,
      resource: 'doc:1',
      permission: 'read',
      granted: true,
      reason: 'Allowed'
    });

    expect(logger.pendingCount()).toBe(1);
    expect(onFlush).not.toHaveBeenCalled();

    logger.log({ timestamp: Date.now(), requestId: 'req_2', tenantId: 1, roleId: 2, resource: 'doc:2', permission: 'read', granted: true, reason: 'Allowed' });
    logger.log({ timestamp: Date.now(), requestId: 'req_3', tenantId: 1, roleId: 2, resource: 'doc:3', permission: 'read', granted: true, reason: 'Allowed' });

    expect(onFlush).toHaveBeenCalledTimes(1);
    expect(logger.pendingCount()).toBe(0);
  });
});

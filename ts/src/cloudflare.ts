import { EdgeRbacClient } from './client.js';
import { EdgeJwtParser, type VerifiedTokenProvider } from './jwt.js';
import { PermissionFlag } from './types.js';

export function createCloudflareRbacMiddleware(client: EdgeRbacClient, verifyToken: VerifiedTokenProvider) {
  if (typeof verifyToken !== 'function') throw new Error('A trusted token verifier is required');
  return async (
    request: Request,
    requiredPermission: PermissionFlag,
    resource: string,
    targetTenantId: number
  ): Promise<Response | null> => {
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return new Response(JSON.stringify({ error: 'Missing or invalid Authorization header' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    try {
      const token = authHeader.slice(7);
      const user = EdgeJwtParser.fromVerifiedClaims(await verifyToken(token));
      const decision = await client.authorize(user, requiredPermission, resource, targetTenantId);

      if (!decision.granted) {
        return new Response(JSON.stringify({ error: 'Forbidden', reason: decision.reason }), {
          status: 403,
          headers: { 'Content-Type': 'application/json' }
        });
      }

      return null; // Authorized, proceed to handler
    } catch (err: any) {
      return new Response(JSON.stringify({ error: 'Authentication failed' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  };
}

import { EdgeRbacClient } from './client.js';
import { EdgeJwtParser, type VerifiedTokenProvider } from './jwt.js';
import { PermissionFlag } from './types.js';

export function createVercelEdgeHandler(client: EdgeRbacClient, verifyToken: VerifiedTokenProvider) {
  if (typeof verifyToken !== 'function') throw new Error('A trusted token verifier is required');
  return async (
    req: Request,
    requiredPermission: PermissionFlag,
    resource: string,
    targetTenantId: number
  ): Promise<{ authorized: boolean; response?: Response; userId?: string }> => {
    const authHeader = req.headers.get('authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return {
        authorized: false,
        response: new Response(JSON.stringify({ error: 'Unauthorized: Missing bearer token' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' }
        })
      };
    }

    try {
      const user = EdgeJwtParser.fromVerifiedClaims(await verifyToken(authHeader.slice(7)));
      const decision = await client.authorize(user, requiredPermission, resource, targetTenantId);

      if (!decision.granted) {
        return {
          authorized: false,
          response: new Response(JSON.stringify({ error: 'Forbidden', reason: decision.reason }), {
            status: 403,
            headers: { 'Content-Type': 'application/json' }
          }),
          userId: user.id
        };
      }

      return { authorized: true, userId: user.id };
    } catch (err: any) {
      return {
        authorized: false,
        response: new Response(JSON.stringify({ error: 'Authentication failed' }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' }
        })
      };
    }
  };
}

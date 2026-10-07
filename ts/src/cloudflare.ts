import { EdgeRbacClient } from './client';
import { EdgeJwtParser } from './jwt';
import { PermissionFlag } from './types';

export function createCloudflareRbacMiddleware(client: EdgeRbacClient) {
  return async (
    request: Request,
    requiredPermission: PermissionFlag,
    resource: string
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
      const user = EdgeJwtParser.toRbacUser(token);
      const decision = await client.authorize(user, requiredPermission, resource);

      if (!decision.granted) {
        return new Response(JSON.stringify({ error: 'Forbidden', reason: decision.reason }), {
          status: 403,
          headers: { 'Content-Type': 'application/json' }
        });
      }

      return null; // Authorized, proceed to handler
    } catch (err: any) {
      return new Response(JSON.stringify({ error: err.message }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  };
}

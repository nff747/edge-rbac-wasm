import { EdgeRbacClient } from './client';
import { EdgeJwtParser } from './jwt';
import { PermissionFlag } from './types';

export function createVercelEdgeHandler(client: EdgeRbacClient) {
  return async (
    req: Request,
    requiredPermission: PermissionFlag,
    resource: string
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
      const user = EdgeJwtParser.toRbacUser(authHeader.slice(7));
      const decision = await client.authorize(user, requiredPermission, resource);

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
        response: new Response(JSON.stringify({ error: err.message }), {
          status: 401,
          headers: { 'Content-Type': 'application/json' }
        })
      };
    }
  };
}

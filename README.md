# worker-auth

Simple User and Session store service for Cloudflare workers

## Example Usage

```ts
import Auth from "@brevitybuilder/worker-auth";
import FaunaStore from "@brevitybuilder/worker-auth/fauna";

export interface Env {}

// setup store and auth
const store = new FaunaStore("fauna secret", "db.us.fauna.com");
const auth = new Auth({ secret: "jwt secret" }, store);

export default {
  async fetch(
    request: Request,
    env: Env,
    ctx: ExecutionContext
  ): Promise<Response> {
    const url = new URL(request.url);
    // let auth handle the auth API routes
    if (url.pathname.startsWith("/api/auth")) {
      return await auth.handle(request);
    }

    // in a request, validate user is authenticated
    const headers = new Headers();
    const user = await auth.getUserFromRequest(request, headers);
    if (user) {
      return new Response("Authenticated", { status: 200, headers });
    }
    return new Response("Not Authenticated!", { status: 401, headers });
  },
};
```

## Available API Routes
- `GET /api/auth/refresh` - Will refresh the stateless JWT using the stateful JWT
- `GET /api/auth/signout` - End session and remove all cookies
- `GET /api/auth/signout/:sessionId` - End session with specific id
- `GET /api/auth/sessions` - Get list of all active sessionId for user
- `POST /api/auth/signup` - Create new user and log in
- `POST /api/auth/signin` - Login user with given credentials

## Available Store Providers
- Fauna

> More providers coming soon.

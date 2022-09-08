import jwt, { JwtPayload } from "@tsndr/cloudflare-worker-jwt";
import { parse as parseCookie, serialize as serializeCookie } from "cookie";
import bcrypt from "bcryptjs";
import { now } from "./utils";

import { CreateUserInput, User } from "./schemas";
import type { Store } from "./stores";

export type Options = {
  secret: string;
};

type ParsedCookies = {
  __stateful?: string;
  __stateless?: string;
};

export const STATEFUL_EXP = 60 * 60 * 24 * 400;
const STATELESS_EXP = 60;

export default class Auth {
  options: Options;
  store: Store;
  constructor(options: Options, store: Store) {
    this.options = options;
    this.store = store;
  }

  public async handle(request: Request) {
    const { method } = request;
    switch (method) {
      case "GET":
        return this.#handleGet(request);
      case "POST":
        return this.#handlePost(request);
      default:
        throw new Error("Not implemented");
    }
  }

  #init(request: Request) {
    const url = new URL(request.url);
    const [action, providerId] = url.pathname.split("/").slice(3);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const headers = Object.fromEntries(request.headers as any);
    const query = Object.fromEntries(url.searchParams);
    const cookies: ParsedCookies = headers.cookie
      ? parseCookie(headers.cookie)
      : {};
    const host = url.hostname;
    return {
      action,
      providerId,
      headers,
      query,
      host,
      cookies,
    };
  }

  async #handleGet(request: Request) {
    const { action, providerId, host, cookies } = this.#init(request);
    switch (action) {
      case "refresh":
        try {
          const payload = await this.#getPayloadFromStatefulCookie(cookies);
          if (!payload) {
            return new Response("Unauthorized", { status: 401 });
          }
          // TODO: see if user record needs updating?
          const newStatelessToken = await this.#makeStatelessToken(
            payload.id,
            payload.user,
            host
          );
          const newStatelessCookie = this.#makeStatelessCookie(
            newStatelessToken,
            host
          );
          return new Response(
            JSON.stringify({
              jwt: newStatelessToken,
              object: "token",
            }),
            {
              status: 200,
              headers: {
                "Content-Type": "application/json",
                "Set-Cookie": newStatelessCookie,
              },
            }
          );
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
        } catch (error: any) {
          console.log("refresh error", error);
          return new Response(error.message, { status: 400 });
        }
      case "signout":
        try {
          if (providerId) {
            await this.store.endSession(providerId);
            return new Response("", {
              status: 204,
              headers: {
                "Set-Cookie": await this.#clearCookies(host),
              },
            });
          }
          if (!cookies.__stateless) {
            return new Response("", {
              status: 204,
              headers: {
                "Set-Cookie": await this.#clearCookies(host),
              },
            });
          }
          const { payload } = jwt.decode(cookies.__stateless);
          await this.store.endSession(payload.sid);
          return new Response("", {
            status: 204,
            headers: {
              "Set-Cookie": await this.#clearCookies(host),
            },
          });
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
        } catch (error: any) {
          console.log("signout error", error);
          return new Response(error.message, { status: 400 });
        }
      case "sessions":
        try {
          const headers = new Headers();
          const user = await this.getUserFromRequest(request, headers);
          if (!user) {
            return new Response("Unauthorized", { status: 401 });
          }
          const sessions = await this.store.getAllSessionsForUser(user.id);
          headers.set("Content-Type", "application/json");
          return new Response(JSON.stringify(sessions), {
            status: 200,
            headers,
          });
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
        } catch (error: any) {
          console.log("sessions error", error);
          return new Response(error.message, { status: 400 });
        }
      default:
        throw new Error("Not implemented");
    }
  }

  async #handlePost(request: Request) {
    const { action, host } = this.#init(request);
    switch (action) {
      case "signin":
        try {
          const body = await request.formData();
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const obj = Object.fromEntries(body as any);
          const userInput = CreateUserInput.parse(obj);
          const user = await this.store.getUserWithHash(userInput.email);
          if (!user) {
            return new Response("Unauthorized", { status: 401 });
          }
          const valid = await bcrypt.compare(userInput.password, user.hash);
          if (!valid) {
            return new Response("Invalid credentials", { status: 401 });
          }
          const sessionId = await this.store.createSession(user.id);
          if (!sessionId) {
            return new Response("Something went wrong", { status: 500 });
          }
          const userWithoutHash = { email: user.email, id: user.id };
          const newStatefulToken = await this.#makeStatefulToken(
            sessionId,
            userWithoutHash,
            host
          );
          const newStatefulCookie = this.#makeStatefulCookie(
            newStatefulToken,
            host
          );
          const newStatelessToken = await this.#makeStatelessToken(
            sessionId,
            userWithoutHash,
            host
          );
          const newStatelessCookie = this.#makeStatelessCookie(
            newStatelessToken,
            host
          );
          return new Response("", {
            status: 204,
            headers: {
              "Set-Cookie": [newStatefulCookie, newStatelessCookie].join(", "),
            },
          });
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
        } catch (error: any) {
          console.log("signin error", error);
          return new Response(error.message, { status: 400 });
        }
      case "signup":
        try {
          const body = await request.formData();
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
          const obj = Object.fromEntries(body as any);
          const userInput = CreateUserInput.parse(obj);
          const hash = bcrypt.hashSync(userInput.password, 10);
          const userRecord = { email: userInput.email };
          const user = await this.store.saveUser({ ...userRecord, hash });
          if (!user) {
            return new Response("Something went wrong", { status: 500 });
          }
          const sessionId = await this.store.createSession(user.id);
          if (!sessionId) {
            return new Response("Something went wrong", { status: 500 });
          }
          const newStatefulToken = await this.#makeStatefulToken(
            sessionId,
            user,
            host
          );
          const newStatefulCookie = this.#makeStatefulCookie(
            newStatefulToken,
            host
          );
          const newStatelessToken = await this.#makeStatelessToken(
            sessionId,
            user,
            host
          );
          const newStatelessCookie = this.#makeStatelessCookie(
            newStatelessToken,
            host
          );
          return new Response(JSON.stringify({ user }), {
            status: 200,
            headers: {
              "Content-Type": "application/json",
              "Set-Cookie": [newStatefulCookie, newStatelessCookie].join(", "),
            },
          });
          // eslint-disable-next-line @typescript-eslint/no-explicit-any
        } catch (error: any) {
          console.log("signup error", error);
          return new Response(error.message, { status: 400 });
        }
      default:
        throw new Error("Not implemented");
    }
  }
  public async getUserFromRequest(
    request: Request,
    headers: Headers = new Headers()
  ): Promise<User | null> {
    try {
      const host = new URL(request.url).hostname;
      const cookies = request.headers.has("cookie")
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
        ? parseCookie(request.headers.get("cookie")!)
        : {};
      let token;
      if (request.headers.has("Authorization")) {
      // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
        token = request.headers.get("Authorization")!.split(" ")[1];
      } else {
        token = cookies.__stateless;
      }
      if (!token) {
        return this.#tryRevalidate(cookies, host, headers);
      }
      const isValid = jwt.verify(token, this.options.secret);
      if (!isValid) {
        return this.#tryRevalidate(cookies, host, headers);
      }
      const { payload } = jwt.decode(token);
      return payload.user;
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
    } catch (error: any) {
      console.log("validate error", error);
      return null;
    }
  }
  async #tryRevalidate(
    cookies: Record<string, string>,
    host: string,
    headers: Headers
  ) {
    if (cookies.__stateful) {
      const isValid = await jwt.verify(cookies.__client__, this.options.secret);
      if (!isValid) {
        headers.set("Set-Cookie", await this.#clearCookies(host));
        return null;
      }
      const { payload } = jwt.decode(cookies.__client__);
      const isActive = await this.store.sessionIsActive(
        payload.user.id,
        payload.id
      );
      if (!isActive) {
        headers.set("Set-Cookie", await this.#clearCookies(host));
        return null;
      }
      const newToken = await this.#makeStatelessToken(
        payload.id,
        payload.user,
        host
      );
      const newCookie = this.#makeStatelessCookie(newToken, host);
      headers.set("Set-Cookie", newCookie);
      // TODO: Do I need to see if the user needs to be updated?
      return payload.user;
    }
    return null;
  }
  async #makeStatelessToken(
    sessionId: string,
    user: User,
    host: string
  ): Promise<string> {
    return await jwt.sign(
      {
        sid: sessionId,
        user: user,
        exp: now() + STATELESS_EXP,
        iss: `https://${host}`,
        nbf: now(),
      },
      this.options.secret
    );
  }
  async #makeStatefulToken(
    sessionId: string,
    user: User,
    host: string
  ): Promise<string> {
    return await jwt.sign(
      {
        id: sessionId,
        user: user,
        exp: now() + STATEFUL_EXP,
        iss: `https://${host}`,
        nbf: now(),
      },
      this.options.secret
    );
  }
  #makeStatelessCookie(token: string, host: string): string {
    return serializeCookie("__stateless", token, {
      domain: host,
      path: "/",
      maxAge: STATELESS_EXP,
      httpOnly: true,
      secure: true,
      sameSite: "lax",
    });
  }
  #makeStatefulCookie(token: string, host: string): string {
    return serializeCookie("__stateful", token, {
      domain: host,
      path: "/",
      maxAge: STATEFUL_EXP,
      httpOnly: true,
      secure: true,
      sameSite: "lax",
    });
  }
  async #clearCookies(host: string) {
    return [
      serializeCookie("__stateless", "", {
        domain: host,
        path: "/",
        maxAge: 0,
        httpOnly: true,
        secure: true,
        sameSite: "lax",
      }),
      serializeCookie("__stateful", "", {
        domain: host,
        path: "/",
        maxAge: 0,
        httpOnly: true,
        secure: true,
        sameSite: "lax",
      }),
    ].join(", ");
  }
  async #getPayloadFromStatefulCookie(
    cookies: ParsedCookies
  ): Promise<JwtPayload | null> {
    if (!cookies.__stateful) {
      return null;
    }
    const isValid = await jwt.verify(cookies.__stateful, this.options.secret);
    if (!isValid) {
      return null;
    }
    const { payload } = jwt.decode(cookies.__stateful);
    const isActive = await this.store.sessionIsActive(
      payload.user.id,
      payload.id
    );
    if (!isActive) {
      return null;
    }
    return payload;
  }
}

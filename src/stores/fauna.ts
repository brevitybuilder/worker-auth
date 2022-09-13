import type { User } from "../schemas";
import type { Store, UserWithHash, UserWithAuthenticators } from "./";
import faunadb from "faunadb";

const q = faunadb.query;

class FaunaStore implements Store {
  client: faunadb.Client;
  constructor(secret: string, domain: string) {
    this.client = new faunadb.Client({
      secret,
      domain,
    });
  }
  async newId(): Promise<string> {
    const res = await this.client.query(q.NewId());
    return res as unknown as string;
  }
  async saveUser(
    user: Omit<UserWithHash, "id"> | Omit<UserWithAuthenticators, "id">,
    id?: string
  ): Promise<User | null> {
    try {
      const data  = {
        email: user.email.toLowerCase(),
      };
      if ("hash" in user) {
        data.hash = user.hash;
      }
      if ("authenticators" in user) {
        data.authenticators = user.authenticators;
      }
      return await this.client.query(
        q.Let(
          {
            user: q.Create(
              id ? q.Ref(q.Collection("users"), id) : q.Collection("users"),
              {
                data,
              }
            ),
          },
          q.Merge(q.Select(["data"], q.Var("user")), {
            id: q.Select(["ref", "id"], q.Var("user")),
            hash: null,
          })
        )
      );
    } catch (e) {
      console.log("error saving user:", e);
      return null;
    }
  }
  async sessionIsActive(userId: string, sessionId: string): Promise<boolean> {
    try {
      await this.client.query(
        q.Get(q.Ref(q.Collection("sessions"), sessionId))
      );
      return true;
    } catch (e) {
      console.log("error getting session:", e);
      return false;
    }
  }
  async createSession(userId: string): Promise<string | null> {
    try {
      return await this.client.query(
        q.Select(
          ["ref", "id"],
          q.Create(q.Collection("sessions"), {
            data: {
              userId,
            },
          })
        )
      );
    } catch (e) {
      console.log("error saving refresh token:", e);
      return null;
    }
  }
  async endSession(sessionId: string): Promise<void> {
    try {
      await this.client.query(
        q.Delete(q.Ref(q.Collection("sessions"), sessionId))
      );
    } catch (e) {
      console.log("error deleting session:", e);
    }
  }
  async getUserWithHash(email: string): Promise<UserWithHash | null> {
    try {
      return await this.client.query(
        q.Let(
          {
            user: q.Get(
              q.Match(q.Index("users_by_email"), email?.toLowerCase())
            ),
          },
          q.Merge(q.Select(["data"], q.Var("user")), {
            id: q.Select(["ref", "id"], q.Var("user")),
          })
        )
      );
    } catch (e) {
      console.log("error getting user with hash:", e);
      return null;
    }
  }
  async getUser(email: string): Promise<User | null> {
    try {
      return await this.client.query(
        q.Let(
          {
            user: q.Get(q.Match(q.Index("users_by_email"), email)),
          },
          q.Merge(q.Select(["data"], q.Var("user")), {
            id: q.Select(["ref", "id"], q.Var("user")),
            hash: null,
          })
        )
      );
    } catch (e) {
      console.log("error getting user:", e);
      return null;
    }
  }
  async getAllSessionsForUser(userId: string): Promise<string[]> {
    try {
      return this.client.query(
        q.Select(
          "data",
          q.Map(
            q.Paginate(q.Match(q.Index("sessions_by_userId"), userId)),
            q.Lambda("X", q.Select("id", q.Var("X")))
          )
        )
      );
    } catch (e) {
      console.log("error getting sessions for user:", e);
      return [];
    }
  }
}

export default FaunaStore;

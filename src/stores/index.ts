import type { User } from "../schemas";

export interface UserWithHash extends User {
  hash: string;
}

export interface UserWithAuthenticators extends User {
  authenticators: any[];
}

export interface Store {
  newId(): Promise<string>;
  saveUser(user: Omit<UserWithHash, "id"> | Omit<UserWithAuthenticators, "id">, id?: string): Promise<User | null>; // must also check that email is unique.
  sessionIsActive(userId: string, sessionId: string): Promise<boolean>;
  createSession(userId: string): Promise<string | null>;
  endSession(sessionId: string): Promise<void>;
  getUser(email: string): Promise<User | null>;
  getUserWithHash(email: string): Promise<UserWithHash | null>;
  getAllSessionsForUser(userId: string): Promise<string[]>;
}

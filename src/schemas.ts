import { z } from "zod";

export const CreateUserInput = z.object({
  email: z.string().email({ message: "Invalid email address" }),
  password: z
    .string()
    .min(6, { message: "Passworld must be 6 or more characters long" }),
});

export const User = z.object({
  id: z.string().uuid(),
  email: z.string().email(),
  authenticators : z.array(z.any()).optional(),
});

export type User = z.infer<typeof User>;

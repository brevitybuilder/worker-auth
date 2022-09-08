import jwt from "@tsndr/cloudflare-worker-jwt";
import { expect, test } from "vitest";

const secret = "secret";

// TODO: write real tests
test("jwt verify", async () => {
  const token = await jwt.sign({ id: 1 }, secret);
  const verified = await jwt.verify(token, secret);
  expect(verified).toBe(true);
  const { payload } = jwt.decode(token);
  // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
  expect(payload!.id).toBe(1);
});

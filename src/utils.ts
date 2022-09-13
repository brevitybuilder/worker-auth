export const now = () => Math.floor(Date.now() / 1000);

export const badRequest = () =>
  new Response(JSON.stringify({ message: "Bad Request", error: true }), {
    status: 400,
    headers: { "content-type": "application/json" },
  });
export const unauthorized = () =>
  new Response(JSON.stringify({ message: "Unauthorized", error: true }), {
    status: 401,
    headers: { "content-type": "application/json" },
  });
export const forbidden = () =>
  new Response(JSON.stringify({ message: "Forbidden", error: true }), {
    status: 403,
    headers: { "content-type": "application/json" },
  });
export const notFound = () =>
  new Response(JSON.stringify({ message: "Not Found", error: true }), {
    status: 404,
    headers: { "content-type": "application/json" },
  });
export const serverError = () =>
  new Response(
    JSON.stringify({ message: "Something went wrong", error: true }),
    { status: 500, headers: { "content-type": "application/json" } }
  );

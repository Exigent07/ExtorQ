/** Liveness for container health checks: no authentication, no details. */
export function GET(): Response {
  return new Response("ok\n", {
    status: 200,
    headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" },
  });
}

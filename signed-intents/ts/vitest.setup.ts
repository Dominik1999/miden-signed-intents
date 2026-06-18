import { readFile } from "node:fs/promises";

// The Miden web SDK loads its WASM by fetching a file:// URL derived from
// import.meta.url. Node's built-in fetch (undici) rejects file:// URLs.
// Polyfill fetch to serve file:// paths from disk so the WASM loads cleanly.
const originalFetch = globalThis.fetch;
globalThis.fetch = (async (input: unknown, init?: unknown) => {
  const url =
    typeof input === "string"
      ? input
      : input instanceof URL
        ? input.href
        : (input as { url?: string })?.url;
  if (typeof url === "string" && url.startsWith("file://")) {
    const bytes = await readFile(new URL(url));
    return new Response(bytes, {
      status: 200,
      headers: { "content-type": "application/wasm" },
    });
  }
  return (originalFetch as (i: unknown, n?: unknown) => Promise<Response>)(
    input,
    init,
  );
}) as typeof fetch;

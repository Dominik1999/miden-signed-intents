import { readFile } from "node:fs/promises";

// The Miden web SDK loads its WASM by fetching a file:// URL derived from
// import.meta.url. Node's built-in fetch (undici) rejects file:// URLs.
// Polyfill fetch to serve file:// paths from disk so the WASM loads cleanly.
//
// This module installs the polyfill as a side effect when imported, so it
// must be the FIRST import in any entry-point that uses @miden-sdk/miden-sdk.
// The eager SDK entry has a top-level await that fires fetch() at module
// evaluation time — the polyfill must already be in place by then.
//
// Also exported as a named function for use cases that prefer explicit opt-in
// (e.g. vitest.setup.ts).
export function installWasmFetchPolyfill(): void {
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
}

// Side-effect install: runs when this module is first evaluated.
installWasmFetchPolyfill();

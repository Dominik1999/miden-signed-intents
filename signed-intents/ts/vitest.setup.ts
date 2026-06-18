// Install the file:// fetch polyfill before any @miden-sdk/miden-sdk use.
// The polyfill is applied as a side effect of importing wasmFetch.
import "./wasmFetch.js";

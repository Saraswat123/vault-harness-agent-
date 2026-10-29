// usage: node tests/seal_interop.mjs <enclavePubHex> <aad> <json>   -> prints the sealed box (what the browser would send)
import { seal } from "../static/seal.js";
const [pub, aad, json] = process.argv.slice(2);
console.log(JSON.stringify(await seal(pub, JSON.parse(json), aad)));

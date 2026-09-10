import { mkdir, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

const parts = [0,1,2,3].map(i => process.env[`VILLAGE_IMAGE_B64_${i}`] || "");
if (parts.some(x => !x)) {
  console.error("Missing restricted village image material");
  process.exit(1);
}
const joined = parts.join("");
let decoded;
try { decoded = Buffer.from(joined, "base64"); }
catch { console.error("Village image base64 decode failed"); process.exit(1); }
if (decoded.length < 100000 || decoded.subarray(0,4).toString("ascii") !== "RIFF" || decoded.subarray(8,12).toString("ascii") !== "WEBP") {
  console.error("Village image integrity check failed");
  process.exit(1);
}
await mkdir(resolve("assets"), { recursive: true });
await Promise.all(parts.map((text, i) => writeFile(resolve(`assets/anans-village.webp.b64.part-${String(i).padStart(2,"0")}`), text, { mode: 0o600 })));
console.log(`Restricted village image materialized: ${decoded.length} bytes`);

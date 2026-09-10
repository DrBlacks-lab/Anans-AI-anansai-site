import { spawn } from "node:child_process";
import { randomBytes, scryptSync } from "node:crypto";

const salt = Buffer.from("00112233445566778899aabbccddeeff", "hex");
if (!process.env.PREVIEW_ADMIN_PASSWORD) {
  console.error("PREVIEW_ADMIN_PASSWORD is required for the local preview launcher");
  process.exit(1);
}
const password = process.env.PREVIEW_ADMIN_PASSWORD;
const passwordRecord = `${salt.toString("hex")}$${scryptSync(password, salt, 64, { N: 16384, r: 8, p: 1 }).toString("hex")}`;
const child = spawn(process.execPath, ["preview-server.mjs"], {
  stdio: "inherit",
  env: {
    ...process.env,
    HOST: process.env.HOST || "127.0.0.1",
    PORT: process.env.PORT || "47937",
    SESSION_SECRET: process.env.SESSION_SECRET || randomBytes(32).toString("hex"),
    ADMIN_USERNAME: process.env.ADMIN_USERNAME || "admin",
    ADMIN_PASSWORD_SCRYPT: process.env.ADMIN_PASSWORD_SCRYPT || passwordRecord,
    GUEST_ACCOUNTS_JSON: process.env.GUEST_ACCOUNTS_JSON || "{}"
  }
});
const stop = signal => { child.kill(signal); };
process.on("SIGINT", () => stop("SIGINT"));
process.on("SIGTERM", () => stop("SIGTERM"));
child.on("exit", code => process.exit(code ?? 0));

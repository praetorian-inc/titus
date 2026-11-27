import { rmSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath } from "url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = resolve(__dirname, "..");

const dirs = [
  resolve(root, "dist"),
  resolve(root, "packages/backend/dist"),
  resolve(root, "packages/frontend/dist"),
];

for (const dir of dirs) {
  try {
    rmSync(dir, { recursive: true, force: true });
  } catch {
    // Directory may not exist
  }
}

console.log("Cleaned dist directories");

import { readFileSync, writeFileSync, existsSync } from "fs";
import { resolve, dirname, relative } from "path";
import { fileURLToPath } from "url";
import JSZip from "jszip";

const __dirname = dirname(fileURLToPath(import.meta.url));
const root = resolve(__dirname, "..");

async function pack() {
  const zip = new JSZip();

  // Add manifest
  const manifest = readFileSync(resolve(root, "manifest.json"), "utf-8");
  zip.file("manifest.json", manifest);

  // Add backend dist
  const backendDist = resolve(root, "packages/backend/dist/index.js");
  if (existsSync(backendDist)) {
    zip.file(
      "packages/backend/dist/index.js",
      readFileSync(backendDist)
    );
  } else {
    console.error("Backend dist not found:", backendDist);
    process.exit(1);
  }

  // Add frontend dist
  const frontendDist = resolve(root, "packages/frontend/dist/index.js");
  if (existsSync(frontendDist)) {
    zip.file(
      "packages/frontend/dist/index.js",
      readFileSync(frontendDist)
    );
  } else {
    console.error("Frontend dist not found:", frontendDist);
    process.exit(1);
  }

  // Add frontend styles
  const frontendStyle = resolve(root, "packages/frontend/dist/style.css");
  if (existsSync(frontendStyle)) {
    zip.file(
      "packages/frontend/dist/style.css",
      readFileSync(frontendStyle)
    );
  }

  // Write zip
  const buffer = await zip.generateAsync({ type: "nodebuffer" });
  const outputPath = resolve(root, "plugin_package.zip");
  writeFileSync(outputPath, buffer);
  console.log(`Plugin packaged: ${relative(root, outputPath)}`);
}

pack().catch((err) => {
  console.error("Pack failed:", err);
  process.exit(1);
});

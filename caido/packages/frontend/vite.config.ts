import { defineConfig } from "vite";

export default defineConfig({
  build: {
    lib: {
      entry: "src/index.ts",
      formats: ["es"],
      fileName: "index",
    },
    outDir: "dist",
    emptyOutDir: true,
    rollupOptions: {
      external: ["@caido/sdk-frontend", "caido:plugin", "caido:utils"],
    },
  },
  css: {
    // Extract CSS into a separate file
  },
});

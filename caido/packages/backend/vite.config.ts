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
      external: [
        "caido:plugin",
        "caido:utils",
        "child_process",
        "path",
        "os",
        "fs",
      ],
    },
  },
});

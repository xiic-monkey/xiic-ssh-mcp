import { resolve } from "node:path";
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  root: "web",
  base: "",  // 相对路径，Tauri 嵌入式资源需要
  server: {
    host: "127.0.0.1",
    port: 1430,
    strictPort: true,
  },
  build: {
    outDir: "../dist",
    emptyOutDir: true,
    rollupOptions: {
      input: {
        main: resolve(__dirname, "web/index.html"),
        approval: resolve(__dirname, "web/approval.html"),
      },
    },
  },
});

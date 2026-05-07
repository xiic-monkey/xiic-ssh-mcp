import { chmodSync, copyFileSync, existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, "..");
const isWindows = process.platform === "win32";
const targetTriple = process.env.TAURI_ENV_TARGET_TRIPLE || process.env.TARGET || "";
const binaryExt = isWindows ? ".exe" : "";

function commandName(name) {
  return isWindows ? `${name}.cmd` : name;
}

function run(cmd, args, options = {}) {
  const result = spawnSync(cmd, args, {
    cwd: repoRoot,
    stdio: "inherit",
    env: process.env,
    ...options,
  });

  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}

function targetDirFor(crateDir) {
  if (!targetTriple) {
    return path.join(repoRoot, crateDir, "target", "release");
  }
  return path.join(repoRoot, crateDir, "target", targetTriple, "release");
}

function rootTargetDir() {
  if (!targetTriple) {
    return path.join(repoRoot, "target", "release");
  }
  return path.join(repoRoot, "target", targetTriple, "release");
}

function copyExecutable(source, destination) {
  if (!existsSync(source)) {
    throw new Error(`Expected binary not found: ${source}`);
  }
  copyFileSync(source, destination);
  if (!isWindows) {
    chmodSync(destination, 0o755);
  }
}

run(commandName("npm"), ["run", "build"]);

const cargoArgs = ["build", "--release"];
if (targetTriple) {
  cargoArgs.push("--target", targetTriple);
}
run("cargo", cargoArgs);
run("cargo", [
  "build",
  "--manifest-path",
  "approval-tauri/Cargo.toml",
  "--release",
  ...(targetTriple ? ["--target", targetTriple] : []),
]);

const bundleDir = path.join(repoRoot, "src-tauri", "bundled-binaries");
rmSync(bundleDir, { recursive: true, force: true });
mkdirSync(bundleDir, { recursive: true });
writeFileSync(path.join(bundleDir, ".gitkeep"), "");

copyExecutable(
  path.join(rootTargetDir(), `xiic-ssh-mcp${binaryExt}`),
  path.join(bundleDir, `xiic-ssh-mcp${binaryExt}`),
);
copyExecutable(
  path.join(targetDirFor("approval-tauri"), `xiic-ssh-approval${binaryExt}`),
  path.join(bundleDir, `xiic-ssh-approval${binaryExt}`),
);

import { chmodSync, copyFileSync, existsSync, mkdirSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { spawnSync } from "node:child_process";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const repoRoot = path.resolve(__dirname, "..");
const isWindows = process.platform === "win32";
const targetTriple =
  process.env.XIIC_BUNDLE_TARGET_TRIPLE ||
  process.env.TAURI_ENV_TARGET_TRIPLE ||
  process.env.TARGET ||
  "";
const binaryExt = isWindows ? ".exe" : "";
const windowsShell = process.env.ComSpec || "cmd.exe";

function commandName(name) {
  if (!isWindows) {
    return name;
  }
  if (name === "cargo") {
    return "cargo.exe";
  }
  return `${name}.cmd`;
}

function log(message) {
  console.log(`[bundle:prepare] ${message}`);
}

function resolveCommand(cmd, args) {
  if (isWindows && cmd.endsWith(".cmd")) {
    return {
      cmd: windowsShell,
      args: ["/d", "/s", "/c", cmd, ...args],
    };
  }

  return { cmd, args };
}

function run(cmd, args, options = {}) {
  const resolved = resolveCommand(cmd, args);
  log(`Running: ${resolved.cmd} ${resolved.args.join(" ")}`);
  const result = spawnSync(resolved.cmd, resolved.args, {
    cwd: repoRoot,
    stdio: "inherit",
    env: process.env,
    ...options,
  });

  if (result.error) {
    console.error(`[bundle:prepare] Failed to start command: ${resolved.cmd}`);
    console.error(result.error);
    process.exit(1);
  }

  if (result.status !== 0) {
    console.error(`[bundle:prepare] Command exited with status ${result.status}: ${resolved.cmd}`);
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
  log(`Copying ${source} -> ${destination}`);
  if (!existsSync(source)) {
    console.error(`[bundle:prepare] Expected binary not found: ${source}`);
    process.exit(1);
  }
  copyFileSync(source, destination);
  if (!isWindows) {
    chmodSync(destination, 0o755);
  }
}

log(`Platform=${process.platform} arch=${process.arch} target=${targetTriple || "<host-default>"}`);

run(commandName("npm"), ["run", "build"]);

const cargoCmd = commandName("cargo");
const cargoArgs = ["build", "--release"];
if (targetTriple) {
  cargoArgs.push("--target", targetTriple);
}
run(cargoCmd, cargoArgs);
run(cargoCmd, [
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

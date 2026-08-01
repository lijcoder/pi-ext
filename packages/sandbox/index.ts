/**
 * Sandbox Extension - OS-level sandboxing for bash + tool_call path rules for file tools
 *
 * Two layers:
 * 1. bash commands run wrapped by @anthropic-ai/sandbox-runtime at the OS level
 *    (sandbox-exec on macOS, bubblewrap on Linux).
 * 2. read/grep/find/ls/write/edit are intercepted via the `tool_call` event and
 *    their paths checked against the same filesystem rules (denyRead for reads,
 *    denyWrite + allowWrite for writes), returning a clear block reason.
 *
 * Note: this example intentionally overrides the built-in `bash` tool to show
 * how built-in tools can be replaced. Alternatively, you could sandbox `bash`
 * via `tool_call` input mutation without replacing the tool.
 *
 * Config files (merged, project takes precedence):
 * - ~/.pi/agent/extensions/sandbox.json (global)
 * - <cwd>/.pi/sandbox.json (project-local)
 *
 * Example .pi/sandbox.json:
 * ```json
 * {
 *   "enabled": true,
 *   "network": {
 *     "allowedDomains": ["github.com", "*.github.com"],
 *     "deniedDomains": []
 *   },
 *   "filesystem": {
 *     "denyRead": ["~/.ssh", "~/.aws"],
 *     "allowWrite": [".", "/tmp"],
 *     "denyWrite": [".env"]
 *   }
 * }
 * ```
 *
 * Usage:
 * - `pi -e ./sandbox` - sandbox enabled with default/config settings
 * - `pi -e ./sandbox --no-sandbox` - disable sandboxing
 * - `/sandbox` - show current sandbox configuration
 *
 * Setup:
 * 1. Copy sandbox/ directory to ~/.pi/agent/extensions/
 * 2. Run `npm install` in ~/.pi/agent/extensions/sandbox/
 *
 * Linux also requires: bubblewrap, socat, ripgrep
 */

import { spawn } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve, sep } from "node:path";
import { SandboxManager, type SandboxRuntimeConfig } from "@anthropic-ai/sandbox-runtime";
import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { type BashOperations, CONFIG_DIR_NAME, createBashTool, getAgentDir, isToolCallEventType, SettingsManager } from "@earendil-works/pi-coding-agent";

interface SandboxConfig extends SandboxRuntimeConfig {
	enabled?: boolean;
}

/** Filesystem rules snapshot used by the tool_call interception layer. */
interface FsRules {
	denyRead: string[];
	allowWrite: string[];
	denyWrite: string[];
}

const DEFAULT_CONFIG: SandboxConfig = {
	enabled: true,
	network: {
		// Default: allow all network access.
		// The extension code treats allowedDomains: ["*"] as "no network
		// restriction" (omit allowedDomains when initializing the runtime,
		// producing (allow network*) on macOS / no net namespace on Linux).
		allowedDomains: ["*"],
		deniedDomains: [],
	},
	filesystem: {
		denyRead: [],
		allowWrite: [".", "/tmp", "/private/tmp"],
		denyWrite: [],
	},
};

function loadConfig(cwd: string, warn?: (message: string) => void): SandboxConfig {
	const projectConfigPath = join(cwd, CONFIG_DIR_NAME, "sandbox.json");
	const globalConfigPath = join(getAgentDir(), "extensions", "sandbox.json");

	let globalConfig: Partial<SandboxConfig> = {};
	let projectConfig: Partial<SandboxConfig> = {};

	if (existsSync(globalConfigPath)) {
		try {
			globalConfig = JSON.parse(readFileSync(globalConfigPath, "utf-8"));
		} catch (e) {
			warn?.(`Sandbox global config parse failed: ${globalConfigPath}: ${e instanceof Error ? e.message : e}`);
		}
	}

	if (existsSync(projectConfigPath)) {
		try {
			projectConfig = JSON.parse(readFileSync(projectConfigPath, "utf-8"));
		} catch (e) {
			warn?.(`Sandbox project config parse failed: ${projectConfigPath}: ${e instanceof Error ? e.message : e}`);
		}
	}

	return deepMerge(deepMerge(DEFAULT_CONFIG, globalConfig), projectConfig);
}

function deepMerge(base: SandboxConfig, overrides: Partial<SandboxConfig>): SandboxConfig {
	const result: SandboxConfig = { ...base };

	if (overrides.enabled !== undefined) result.enabled = overrides.enabled;
	if (overrides.network) {
		result.network = { ...base.network, ...overrides.network };
	}
	if (overrides.filesystem) {
		result.filesystem = { ...base.filesystem, ...overrides.filesystem };
	}

	const extOverrides = overrides as {
		ignoreViolations?: Record<string, string[]>;
		enableWeakerNestedSandbox?: boolean;
	};
	const extResult = result as { ignoreViolations?: Record<string, string[]>; enableWeakerNestedSandbox?: boolean };

	if (extOverrides.ignoreViolations) {
		extResult.ignoreViolations = extOverrides.ignoreViolations;
	}
	if (extOverrides.enableWeakerNestedSandbox !== undefined) {
		extResult.enableWeakerNestedSandbox = extOverrides.enableWeakerNestedSandbox;
	}

	return result;
}

// ---------------------------------------------------------------------------
// tool_call path rules (Layer: in-process read/write interception)
// ---------------------------------------------------------------------------

function hasGlobChars(p: string): boolean {
	return p.includes("*") || p.includes("?") || p.includes("{") || p.includes("[");
}

/** Convert a glob (with *, **, ?) to an anchored regex. */
function globToRegExp(glob: string): RegExp {
	let re = "";
	for (let i = 0; i < glob.length; i++) {
		const c = glob[i];
		if (c === "*") {
			if (glob[i + 1] === "*") {
				if (glob[i + 2] === "/") {
					re += "(?:.*/)?"; // **/ spans zero or more directories
					i += 2;
				} else {
					re += ".*"; // bare ** crosses path separators
					i++;
				}
			} else {
				re += "[^/]*";
			}
		} else if (c === "?") {
			re += "[^/]";
		} else if ("\\^$.|+()[]{}".includes(c)) {
			re += "\\" + c;
		} else {
			re += c;
		}
	}
	return new RegExp("^" + re + "$");
}

/** Expand ~ and resolve a path (rule pattern or tool target) against cwd. */
function normalizeRulePath(raw: string, cwd: string): string {
	if (raw === "~") return homedir();
	if (raw.startsWith("~/")) return join(homedir(), raw.slice(2));
	return resolve(cwd, raw);
}

/**
 * Does `target` match `pattern`? Literal patterns match the path itself and
 * everything below it (mirroring sandbox-exec subpath semantics). Glob
 * patterns match the path or any of its ancestor directories.
 */
function matchesRule(target: string, pattern: string, cwd: string): boolean {
	const p = normalizeRulePath(pattern, cwd);
	if (hasGlobChars(p)) {
		const re = globToRegExp(p);
		if (re.test(target)) return true;
		let dir = dirname(target);
		while (dir !== dirname(dir)) {
			if (re.test(dir)) return true;
			dir = dirname(dir);
		}
		return false;
	}
	return target === p || target.startsWith(p + sep);
}

/** Returns a blocking reason, or undefined if the path is allowed. */
function checkPathRules(rawPath: string, verb: "read" | "write", cwd: string, rules: FsRules): string | undefined {
	const target = normalizeRulePath(rawPath, cwd);

	if (verb === "read") {
		for (const pattern of rules.denyRead) {
			if (matchesRule(target, pattern, cwd)) {
				return `read: ${rawPath}: Operation not permitted`;
			}
		}
		return undefined;
	}

	for (const pattern of rules.denyWrite) {
		if (matchesRule(target, pattern, cwd)) {
			return `write: ${rawPath}: Operation not permitted`;
		}
	}
	if (rules.allowWrite.length > 0 && !rules.allowWrite.some((p) => matchesRule(target, p, cwd))) {
		return `write: ${rawPath}: Operation not permitted (outside the allowed directories)`;
	}
	return undefined;
}

function createSandboxedBashOps(): BashOperations {
	return {
		async exec(command, cwd, { onData, signal, timeout }) {
			if (!existsSync(cwd)) {
				throw new Error(`Working directory does not exist: ${cwd}`);
			}

			const wrappedCommand = await SandboxManager.wrapWithSandbox(command);

			return new Promise((resolve, reject) => {
				const child = spawn("bash", ["-c", wrappedCommand], {
					cwd,
					detached: true,
					stdio: ["ignore", "pipe", "pipe"],
				});

				let timedOut = false;
				let timeoutHandle: NodeJS.Timeout | undefined;

				if (timeout !== undefined && timeout > 0) {
					timeoutHandle = setTimeout(() => {
						timedOut = true;
						if (child.pid) {
							try {
								process.kill(-child.pid, "SIGKILL");
							} catch {
								child.kill("SIGKILL");
							}
						}
					}, timeout * 1000);
				}

				child.stdout?.on("data", onData);
				child.stderr?.on("data", onData);

				child.on("error", (err) => {
					if (timeoutHandle) clearTimeout(timeoutHandle);
					reject(err);
				});

				const onAbort = () => {
					if (child.pid) {
						try {
							process.kill(-child.pid, "SIGKILL");
						} catch {
							child.kill("SIGKILL");
						}
					}
				};

				signal?.addEventListener("abort", onAbort, { once: true });

				child.on("close", (code) => {
					if (timeoutHandle) clearTimeout(timeoutHandle);
					signal?.removeEventListener("abort", onAbort);

					if (signal?.aborted) {
						reject(new Error("aborted"));
					} else if (timedOut) {
						reject(new Error(`timeout:${timeout}`));
					} else {
						resolve({ exitCode: code });
					}
				});
			});
		},
	};
}

export default function (pi: ExtensionAPI) {
	pi.registerFlag("no-sandbox", {
		description: "Disable OS-level sandboxing for bash commands",
		type: "boolean",
		default: false,
	});

	const localCwd = process.cwd();
	const localBash = createBashTool(localCwd);

	let sandboxEnabled = false;
	let sandboxInitialized = false;
	let activeRules: FsRules | undefined;
	// Cached SettingsManager + captured prefix, refreshed once per session
	// (session_start fires on startup and /reload — same lifecycle point where
	// pi itself reloads settings). Tool execution only touches in-memory values,
	// no file I/O.
	let settings: SettingsManager | undefined;
	let shellCommandPrefix: string | undefined;

	pi.registerTool({
		...localBash,
		label: "bash (sandboxed)",
		async execute(id, params, signal, onUpdate, _ctx) {
			// pi only injects shellCommandPrefix into its own built-in tool, so
			// our replacement must apply it itself. Value is fixed per session,
			// matching how pi's own bash tool captures it at session start.
			const bash = createBashTool(localCwd, {
				commandPrefix: shellCommandPrefix,
				operations: sandboxEnabled && sandboxInitialized ? createSandboxedBashOps() : undefined,
			});
			return bash.execute(id, params, signal, onUpdate);
		},
	});

	// Layer: in-process path-rule interception for the file tools
	// (read/grep/find/ls -> denyRead; write/edit -> denyWrite + allowWrite).
	// bash is intentionally excluded: its command text is not reliably
	// parseable, and the OS-level sandbox already enforces the same rules.
	// Rules follow the sandbox switch: disabled/unsupported -> no interception.
	pi.on("tool_call", async (event, ctx) => {
		if (!sandboxEnabled || !activeRules) return;

		let rawPath: string | undefined;
		let verb: "read" | "write" | undefined;

		if (isToolCallEventType("read", event)) {
			rawPath = event.input.path;
			verb = "read";
		} else if (isToolCallEventType("grep", event)) {
			// path defaults to the current directory when omitted
			rawPath = event.input.path ?? ctx.cwd;
			verb = "read";
		} else if (isToolCallEventType("find", event)) {
			rawPath = event.input.path ?? ctx.cwd;
			verb = "read";
		} else if (isToolCallEventType("ls", event)) {
			rawPath = event.input.path ?? ctx.cwd;
			verb = "read";
		} else if (isToolCallEventType("write", event)) {
			rawPath = event.input.path;
			verb = "write";
		} else if (isToolCallEventType("edit", event)) {
			rawPath = event.input.path;
			verb = "write";
		}
		if (!rawPath || !verb) return;

		const reason = checkPathRules(rawPath, verb, ctx.cwd, activeRules);
		if (reason) return { block: true, reason };
	});

	pi.on("user_bash", () => {
		if (!sandboxEnabled || !sandboxInitialized) return;
		return { operations: createSandboxedBashOps() };
	});

	pi.on("session_start", async (_event, ctx) => {
		// Refresh pi settings once per session (matches pi's own lifecycle:
		// settingsManager.reload() runs at session start and on /reload, so
		// mid-session file edits aren't picked up by pi itself either).
		// Mirror project-trust handling so an untrusted project's .pi/settings.json
		// is ignored, exactly like pi's runtime does.
		try {
			settings ??= SettingsManager.create(ctx.cwd);
			settings.setProjectTrusted(ctx.isProjectTrusted());
			await settings.reload();
			shellCommandPrefix = settings.getShellCommandPrefix();
		} catch (e) {
			ctx.ui.notify(`Sandbox shellCommandPrefix config load failed: ${e instanceof Error ? e.message : e}`, "warning");
		}

		const noSandbox = pi.getFlag("no-sandbox") as boolean;

		if (noSandbox) {
			sandboxEnabled = false;
			activeRules = undefined;
			ctx.ui.notify("Sandbox disabled via --no-sandbox", "warning");
			return;
		}

		const config = loadConfig(ctx.cwd, (msg) => ctx.ui.notify(msg, "warning"));

		if (!config.enabled) {
			sandboxEnabled = false;
			activeRules = undefined;
			ctx.ui.notify("Sandbox disabled via config", "info");
			return;
		}

		// Snapshot the path rules for the tool_call layer. They are only
		// evaluated while sandboxEnabled is true (see the tool_call handler),
		// so the disable paths below reset them to undefined.
		activeRules = config.filesystem
			? {
					denyRead: config.filesystem.denyRead ?? [],
					allowWrite: config.filesystem.allowWrite ?? [],
					denyWrite: config.filesystem.denyWrite ?? [],
				}
			: undefined;

		const platform = process.platform;
		if (platform !== "darwin" && platform !== "linux") {
			sandboxEnabled = false;
			activeRules = undefined;
			ctx.ui.notify(`Sandbox not supported on ${platform}`, "warning");
			return;
		}

		try {
			const configExt = config as unknown as {
				ignoreViolations?: Record<string, string[]>;
				enableWeakerNestedSandbox?: boolean;
			};

			// "allowedDomains: [\"*\"]" means allow all network access.
			// The runtime's wrapCommandWithSandbox only applies network
			// restrictions when network.allowedDomains !== undefined, so we pass
			// a network object WITHOUT the allowedDomains key to get a full
			// allow-all profile (macOS: (allow network*); Linux: no net namespace
			// isolation). initialize() still needs the network key to exist (it
			// reads httpProxyPort from it), so we can't omit it.
			const allowAllNetwork = config.network?.allowedDomains?.includes("*") === true;

			// The runtime checks for the *presence* of the allowedDomains key at
			// runtime, so omitting it is fine despite the type requiring it.
			const networkConfig = allowAllNetwork
				? ({ deniedDomains: [] } as unknown as NonNullable<typeof config.network>)
				: config.network;

			await SandboxManager.initialize({
				network: networkConfig,
				filesystem: config.filesystem,
				ignoreViolations: configExt.ignoreViolations,
				enableWeakerNestedSandbox: configExt.enableWeakerNestedSandbox,
			});

			sandboxEnabled = true;
			sandboxInitialized = true;

			const networkCount = config.network?.allowedDomains?.length ?? 0;
			const writeCount = config.filesystem?.allowWrite?.length ?? 0;
			ctx.ui.setStatus(
				"sandbox",
				ctx.ui.theme.fg("accent", `🔒 Sandbox: ${networkCount} domains, ${writeCount} write paths`),
			);
			ctx.ui.notify("Sandbox initialized", "info");
		} catch (err) {
			sandboxEnabled = false;
			activeRules = undefined;
			ctx.ui.notify(`Sandbox initialization failed: ${err instanceof Error ? err.message : err}`, "error");
		}
	});

	pi.on("session_shutdown", async () => {
		if (sandboxInitialized) {
			try {
				await SandboxManager.reset();
			} catch {
				// Ignore cleanup errors
			}
		}
	});

	pi.registerCommand("sandbox", {
		description: "Show sandbox configuration",
		handler: async (_args, ctx) => {
			if (!sandboxEnabled) {
				ctx.ui.notify("Sandbox is disabled", "info");
				return;
			}

			const config = loadConfig(ctx.cwd, (msg) => ctx.ui.notify(msg, "warning"));
			const lines = [
				"Sandbox Configuration:",
				"",
				`Enabled: ${config?.enabled || true}`,
				"ToolCall interception (read/grep/find/ls -> denyRead, write/edit -> denyWrite+allowWrite):",
				`  Active: ${sandboxEnabled && activeRules ? "yes" : "no"}`,
				"Network:",
				`  Allowed: ${config.network?.allowedDomains?.join(", ") || "(none)"}`,
				`  Denied: ${config.network?.deniedDomains?.join(", ") || "(none)"}`,
				"",
				"Filesystem:",
				`  Deny Read: ${config.filesystem?.denyRead?.join(", ") || "(none)"}`,
				`  Allow Write: ${config.filesystem?.allowWrite?.join(", ") || "(none)"}`,
				`  Deny Write: ${config.filesystem?.denyWrite?.join(", ") || "(none)"}`,
			];
			ctx.ui.notify(lines.join("\n"), "info");
		},
	});
}

/**
 * Permission Rules Extension
 *
 * Claude Code-style configurable permission gate. Rules are declared in JSON
 * config files and matched against tool calls with three outcomes: allow, deny,
 * ask (prompt the user). Supports bash commands and path-based tools
 * (read/edit/write/grep/find/ls) using glob patterns.
 *
 * Config locations (project overrides global):
 *   ~/.pi/agent/extensions/permission-rules.json   (global)
 *   .pi/permission-rules.json           (project-local, trusted projects only)
 *
 * Config schema:
 * {
 *   "default": "allow",         // action when no rule matches: "allow" | "deny" | "ask"
 *   "abortOnBlock": true,        // when true (default), blocking also aborts the
 *                               // agent turn so it stops and waits for input
 *                               // instead of continuing with the block reason
 *   "rules": {
 *     "allow": [
 *       "Bash(git status)",
 *       "Bash(npm run test:*)",
 *       "Read(src/**)",
 *       "Edit(src/**)"
 *     ],
 *     "deny": [
 *       "Bash(rm -rf *)",
 *       "Bash(sudo *)",
 *       "Read(.env*)",
 *       "Edit(.env*)",
 *       "Write(.git/**)"
 *     ],
 *     "ask": [
 *       "Bash(git push:*)"
 *     ]
 *   }
 * }
 *
 * Rule syntax:  ToolName(pattern)
 *   - ToolName: bash | read | edit | write | grep | find | ls
 *   - pattern: glob matched against the tool's subject string
 *       * bash  -> the command string
 *       * read/edit/write/grep/find/ls -> the path argument
 *   - glob:  * matches any sequence, ? matches a single char, ** matches
 *           across path separators (treated as *). Other chars are literal.
 *   - "ToolName(*)" matches any call of that tool.
 *
 * Priority: deny > allow > ask > default.
 *
 * Non-interactive mode (no UI, e.g. `pi -p`): all tool calls pass through
 * without gating; rules only apply in interactive TUI mode.
 */

import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import type { ExtensionAPI, ExtensionContext, ToolCallEvent } from "@earendil-works/pi-coding-agent";
import { CONFIG_DIR_NAME, getAgentDir } from "@earendil-works/pi-coding-agent";

type Action = "allow" | "deny" | "ask";

interface RulesConfig {
	default?: Action;
	/** When true (default), blocking a tool also aborts the agent turn so it
	 *  stops and waits for new input instead of continuing with the block
	 *  reason as a tool error. */
	abortOnBlock?: boolean;
	rules?: {
		allow?: RuleEntry[];
		deny?: RuleEntry[];
		ask?: RuleEntry[];
	};
}

interface RuleEntry {
	tool: string;
	pattern: string;
	re: RegExp;
	/** Original source string for display. */
	source: string;
	reason?: string;
}

interface ParsedConfig {
	default: Action;
	abortOnBlock?: boolean;
	deny: RuleEntry[];
	allow: RuleEntry[];
	ask: RuleEntry[];
}

/** Convert a glob pattern to an anchored RegExp. `*` -> any sequence, `?` -> one char. */
function globToRegExp(glob: string): RegExp {
	let re = "";
	for (let i = 0; i < glob.length; i++) {
		const c = glob[i];
		if (c === "*") {
			// Collapse ** into a single greedy match.
			re += ".*";
			if (glob[i + 1] === "*") i++;
		} else if (c === "?") {
			re += ".";
		} else if (c === "[" || c === "]" || c === "(" || c === ")" || c === "{" || c === "}" || c === "." || c === "+" || c === "^" || c === "$" || c === "|" || c === "\\" || c === "/") {
			re += "\\" + c;
		} else {
			re += c;
		}
	}
	return new RegExp("^" + re + "$", "i");
}

function parseRuleEntry(raw: unknown): RuleEntry | undefined {
	if (typeof raw === "string") {
		return parseRuleString(raw);
	}
	if (raw && typeof raw === "object") {
		const obj = raw as { pattern?: string; reason?: string };
		if (typeof obj.pattern !== "string") return undefined;
		const parsed = parseRuleString(obj.pattern);
		if (!parsed) return undefined;
		parsed.reason = typeof obj.reason === "string" ? obj.reason : undefined;
		return parsed;
	}
	return undefined;
}

function parseRuleString(source: string): RuleEntry | undefined {
	const open = source.indexOf("(");
	const close = source.lastIndexOf(")");
	if (open <= 0 || close <= open) return undefined;
	const tool = source.slice(0, open).trim().toLowerCase();
	const pattern = source.slice(open + 1, close);
	if (!tool) return undefined;
	return { tool, pattern, re: globToRegExp(pattern), source };
}

function parseConfig(raw: unknown): ParsedConfig {
	const cfg = (raw ?? {}) as RulesConfig;
	const defaultAction: Action = cfg.default === "allow" || cfg.default === "deny" || cfg.default === "ask" ? cfg.default : "allow";
	const abortOnBlock = cfg.abortOnBlock;
	const toEntries = (list: unknown): RuleEntry[] => {
		if (!Array.isArray(list)) return [];
		const entries: RuleEntry[] = [];
		for (const item of list) {
			const entry = parseRuleEntry(item);
			if (entry) entries.push(entry);
		}
		return entries;
	};
	return {
		default: defaultAction,
		abortOnBlock,
		deny: toEntries(cfg.rules?.deny),
		allow: toEntries(cfg.rules?.allow),
		ask: toEntries(cfg.rules?.ask),
	};
}

function loadConfig(cwd: string): ParsedConfig {
	const globalPath = join(getAgentDir(), "extensions", "permission-rules.json");
	const projectPath = join(cwd, CONFIG_DIR_NAME, "permission-rules.json");

	let global: ParsedConfig | undefined;
	let project: ParsedConfig | undefined;

	for (const [p, label] of [[globalPath, "global"], [projectPath, "project"]] as const) {
		if (!existsSync(p)) continue;
		try {
			const parsed = parseConfig(JSON.parse(readFileSync(p, "utf-8")));
			if (label === "global") global = parsed;
			else project = parsed;
		} catch (err) {
			console.error(`permission-rules: failed to load ${label} config ${p}: ${err}`);
		}
	}

	if (!global && !project) {
		return { default: "allow", abortOnBlock: true, deny: [], allow: [], ask: [] };
	}
	if (!project) return { ...global!, abortOnBlock: global!.abortOnBlock ?? true };
	if (!global) return { ...project, abortOnBlock: project.abortOnBlock ?? true };

	// Project extends global: project rules are appended after global rules so
	// project-specific entries win on ties (first match wins, so earlier wins).
	return {
		default: project.default ?? global.default,
		abortOnBlock: project.abortOnBlock ?? global.abortOnBlock ?? true,
		deny: [...global.deny, ...project.deny],
		allow: [...global.allow, ...project.allow],
		ask: [...global.ask, ...project.ask],
	};
}

/** Extract the subject string a rule pattern matches against for a tool call. */
function subjectForTool(event: ToolCallEvent): string | undefined {
	// ToolCallEvent is not a clean discriminated union (CustomToolCallEvent has
	// toolName: string), so we read input fields via a typed record.
	const input = event.input as Record<string, unknown>;
	switch (event.toolName) {
		case "bash":
			return typeof input.command === "string" ? input.command : undefined;
		case "read":
		case "edit":
		case "write":
			return typeof input.path === "string" ? input.path : undefined;
		case "grep":
		case "find":
		case "ls":
			return typeof input.path === "string" ? input.path : ".";
		default:
			return undefined;
	}
}

function matchEntry(entries: RuleEntry[], tool: string, subject: string): RuleEntry | undefined {
	for (const entry of entries) {
		if (entry.tool !== tool) continue;
		if (entry.re.test(subject)) return entry;
	}
	return undefined;
}

function describeAction(action: Action, entry: RuleEntry | undefined, tool: string, subject: string): string {
	const where = entry ? ` (rule: ${entry.source}${entry.reason ? ` — ${entry.reason}` : ""})` : " (default)";
	return `${action}${where} for ${tool}: ${subject}`;
}

export default function permissionRulesExtension(pi: ExtensionAPI) {
	let config: ParsedConfig = { default: "allow", abortOnBlock: true, deny: [], allow: [], ask: [] };

	function reload(ctx: ExtensionContext) {
		config = loadConfig(ctx.cwd);
	}

	pi.on("session_start", async (_event, ctx) => {
		// Reload on every session start so cwd changes (e.g. /resume into another
		// project) pick up the right config.
		reload(ctx);
	});

	pi.on("tool_call", async (event, ctx) => {
		const subject = subjectForTool(event);
		if (subject === undefined) return undefined;
		const tool = event.toolName;

		// Non-interactive mode: pass through, no gating.
		if (!ctx.hasUI) return undefined;

		// When true, blocking also aborts the agent turn so it stops and waits
		// for new input instead of continuing with the block reason as a tool error.
		const block = (reason: string) => {
			if (config.abortOnBlock) ctx.abort();
			return { block: true, reason };
		};

		// Priority: deny > allow > ask > default.
		const denyHit = matchEntry(config.deny, tool, subject);
		if (denyHit) {
			return block(describeAction("deny", denyHit, tool, subject));
		}

		const allowHit = matchEntry(config.allow, tool, subject);
		if (allowHit) {
			// Explicitly allowed; fall through to other handlers / execution.
			return undefined;
		}

		const askHit = matchEntry(config.ask, tool, subject);
		const action: Action = askHit ? "ask" : config.default;
		const entry = askHit ?? undefined;

		if (action === "allow") return undefined;
		if (action === "deny") {
			return block(describeAction("deny", entry, tool, subject));
		}

		// ask (interactive only — non-UI handled at the top of the handler)
		const choice = await ctx.ui.select(`Run ${tool}?\n\n  ${subject}`, [
			"Yes, allow once",
			"No, block",
		]);
		if (!choice?.startsWith("Yes")) {
			return block(`Blocked by user: ${tool}: ${subject}`);
		}
		return undefined;
	});
}

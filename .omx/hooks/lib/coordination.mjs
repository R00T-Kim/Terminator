import { existsSync, readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const MODULE_DIR = dirname(fileURLToPath(import.meta.url));
const FALLBACK_PROJECT_ROOT = resolve(MODULE_DIR, '../../..');

export function safeString(value, fallback = '') {
  return typeof value === 'string' && value.trim() ? value : fallback;
}

export function findProjectRoot(startCwd = process.cwd()) {
  let current = resolve(startCwd || process.cwd());
  while (true) {
    if (existsSync(join(current, 'tools', 'coordination_cli.py'))) {
      return current;
    }
    const parent = dirname(current);
    if (parent === current) {
      break;
    }
    current = parent;
  }
  return FALLBACK_PROJECT_ROOT;
}

export function normalizeCwd(event) {
  return safeString(event?.context?.project_path, process.cwd());
}

function parseJson(stdout) {
  try {
    return JSON.parse(stdout);
  } catch {
    return null;
  }
}

function runPythonJson(scriptRelativePath, args, options = {}) {
  const cwd = resolve(options.cwd || process.cwd());
  const projectRoot = findProjectRoot(cwd);
  const scriptPath = join(projectRoot, scriptRelativePath);
  const result = spawnSync('python3', [scriptPath, ...args], {
    cwd: projectRoot,
    env: { ...process.env, ...(options.env || {}) },
    encoding: 'utf-8',
    input: options.input,
  });

  const stdout = (result.stdout || '').trim();
  const stderr = (result.stderr || '').trim();
  const data = stdout ? parseJson(stdout) : null;
  return {
    ok: result.status === 0 && data !== null,
    status: result.status ?? 1,
    stdout,
    stderr,
    data,
    projectRoot,
    scriptPath,
  };
}

export function runCoordinationCli(args, options = {}) {
  return runPythonJson('tools/coordination_cli.py', args, options);
}

export function runContextDigest(args, options = {}) {
  return runPythonJson('tools/context_digest.py', args, options);
}

export function readOmxSessionId(cwd) {
  const projectRoot = findProjectRoot(cwd);
  const sessionPath = join(projectRoot, '.omx', 'state', 'session.json');
  if (!existsSync(sessionPath)) {
    return '';
  }
  try {
    const payload = JSON.parse(readFileSync(sessionPath, 'utf-8'));
    return safeString(payload?.session_id);
  } catch {
    return '';
  }
}

export function resolveSessionId(event, cwd = normalizeCwd(event)) {
  return safeString(event?.session_id) || readOmxSessionId(cwd);
}

export function summarizeEvent(event, headline) {
  const lines = [headline];
  const reason = safeString(event?.context?.reason);
  if (reason) {
    lines.push(`- Reason: ${reason}`);
  }

  const preview = safeString(event?.context?.output_preview).slice(0, 400);
  if (preview) {
    lines.push(`- Output preview: ${preview}`);
  }

  const messages = Array.isArray(event?.context?.input_messages) ? event.context.input_messages : [];
  const latestInput = messages.length > 0 ? safeString(messages[messages.length - 1]) : '';
  if (latestInput) {
    lines.push(`- Latest input: ${latestInput.slice(0, 400)}`);
  }

  const turnId = safeString(event?.turn_id);
  if (turnId) {
    lines.push(`- Turn id: ${turnId}`);
  }

  return lines.join('\n');
}

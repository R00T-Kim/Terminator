import { normalizeCwd, resolveSessionId, runCoordinationCli } from './lib/coordination.mjs';

export async function onHookEvent(event, sdk) {
  if (event.event !== 'session-start') {
    return;
  }

  const cwd = normalizeCwd(event);
  const sessionId = resolveSessionId(event, cwd);
  const args = ['bootstrap-codex', '--cwd', cwd];
  if (sessionId) {
    args.push('--session', sessionId);
  }

  const result = runCoordinationCli(args, { cwd });
  if (!result.ok || !result.data) {
    await sdk.log.error('coordination bootstrap failed', {
      cwd,
      status: result.status,
      stderr: result.stderr,
      stdout: result.stdout,
    });
    return;
  }

  await sdk.state.write('coordination.last_bootstrap', {
    session_id: result.data.session_id,
    latest_digest_ref: result.data.latest_digest?.path || null,
    latest_handoff_ref: result.data.latest_handoff?.path || null,
    at: event.timestamp,
  });

  await sdk.log.info('coordination bootstrap completed', {
    session_id: result.data.session_id,
    skill_count: result.data.skills?.count || 0,
    instruction_count: result.data.instructions?.count || 0,
    latest_digest_ref: result.data.latest_digest?.path || null,
    latest_handoff_ref: result.data.latest_handoff?.path || null,
  });
}

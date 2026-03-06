import {
  normalizeCwd,
  resolveSessionId,
  runContextDigest,
  runCoordinationCli,
  summarizeEvent,
} from './lib/coordination.mjs';

export async function onHookEvent(event, sdk) {
  if (event.event !== 'session-idle') {
    return;
  }

  const cwd = normalizeCwd(event);
  const sessionId = resolveSessionId(event, cwd);
  if (!sessionId) {
    await sdk.log.warn('coordination idle sync skipped: session_id unavailable', { cwd });
    return;
  }

  const syncResult = runCoordinationCli(['sync-omx-state', '--session', sessionId, '--cwd', cwd], { cwd });
  const statusResult = runCoordinationCli(['session-status', '--session', sessionId], { cwd });
  const handoffResult = runCoordinationCli(['consume-handoff', '--session', sessionId, '--to', 'codex'], { cwd });

  if (!syncResult.ok || !statusResult.ok || !handoffResult.ok) {
    await sdk.log.error('coordination idle sync failed', {
      session_id: sessionId,
      sync_status: syncResult.status,
      status_status: statusResult.status,
      handoff_status: handoffResult.status,
      sync_stderr: syncResult.stderr,
      status_stderr: statusResult.stderr,
      handoff_stderr: handoffResult.stderr,
    });
    return;
  }

  const text = [
    summarizeEvent(event, '[OMX SESSION IDLE SYNC]'),
    `- Session id: ${sessionId}`,
    `- Pending handoff: ${statusResult.data?.pending_handoff ? 'yes' : 'no'}`,
    `- Current leader: ${statusResult.data?.current_leader || 'unknown'}`,
    `- Latest digest: ${statusResult.data?.latest_digest?.path || 'none'}`,
    `- Latest codex handoff: ${handoffResult.data?.handoff?.path || 'none'}`,
    `- Artifact count: ${statusResult.data?.artifact_count || 0}`,
  ].join('\n');

  const digestResult = runContextDigest(
    [
      '--session',
      sessionId,
      '--cwd',
      cwd,
      '--kind',
      'omx_session_idle',
      '--title',
      'OMX session idle snapshot',
      '--generated-by',
      'omx_hook_session_idle',
      '--text',
      text,
    ],
    { cwd },
  );

  await sdk.state.write('coordination.last_idle_sync', {
    session_id: sessionId,
    pending_handoff: Boolean(statusResult.data?.pending_handoff),
    latest_handoff_ref: handoffResult.data?.handoff?.path || null,
    latest_digest_ref: digestResult.data?.path || statusResult.data?.latest_digest?.path || null,
    at: event.timestamp,
  });

  if (!digestResult.ok) {
    await sdk.log.warn('coordination idle digest failed', {
      session_id: sessionId,
      status: digestResult.status,
      stderr: digestResult.stderr,
      stdout: digestResult.stdout,
    });
    return;
  }

  await sdk.log.info('coordination idle sync completed', {
    session_id: sessionId,
    pending_handoff: Boolean(statusResult.data?.pending_handoff),
    latest_handoff_ref: handoffResult.data?.handoff?.path || null,
    latest_digest_ref: digestResult.data?.path || null,
  });
}

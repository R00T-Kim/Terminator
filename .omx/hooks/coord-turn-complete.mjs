import {
  normalizeCwd,
  resolveSessionId,
  runContextDigest,
  runCoordinationCli,
  summarizeEvent,
} from './lib/coordination.mjs';

export async function onHookEvent(event, sdk) {
  if (event.event !== 'turn-complete') {
    return;
  }

  const cwd = normalizeCwd(event);
  const sessionId = resolveSessionId(event, cwd);
  if (!sessionId) {
    await sdk.log.warn('coordination turn sync skipped: session_id unavailable', { cwd });
    return;
  }

  const syncResult = runCoordinationCli(['sync-omx-state', '--session', sessionId, '--cwd', cwd], { cwd });
  if (!syncResult.ok || !syncResult.data) {
    await sdk.log.error('coordination turn sync failed', {
      session_id: sessionId,
      status: syncResult.status,
      stderr: syncResult.stderr,
      stdout: syncResult.stdout,
    });
    return;
  }

  const text = [
    summarizeEvent(event, '[OMX TURN COMPLETE SYNC]'),
    `- Session id: ${sessionId}`,
    `- OMX root: ${syncResult.data.omx_root || 'unknown'}`,
    `- Synced artifacts: ${(syncResult.data.artifacts || []).length}`,
    `- Latest digest: ${syncResult.data.latest_digest?.path || 'none'}`,
  ].join('\n');

  const digestResult = runContextDigest(
    [
      '--session',
      sessionId,
      '--cwd',
      cwd,
      '--kind',
      'omx_turn_complete',
      '--title',
      'OMX turn complete snapshot',
      '--generated-by',
      'omx_hook_turn_complete',
      '--text',
      text,
    ],
    { cwd },
  );

  await sdk.state.write('coordination.last_turn_sync', {
    session_id: sessionId,
    latest_digest_ref: digestResult.data?.path || syncResult.data.latest_digest?.path || null,
    artifact_count: (syncResult.data.artifacts || []).length,
    at: event.timestamp,
  });

  if (!digestResult.ok) {
    await sdk.log.warn('coordination turn digest failed', {
      session_id: sessionId,
      status: digestResult.status,
      stderr: digestResult.stderr,
      stdout: digestResult.stdout,
    });
    return;
  }

  await sdk.log.info('coordination turn sync completed', {
    session_id: sessionId,
    artifact_count: (syncResult.data.artifacts || []).length,
    latest_digest_ref: digestResult.data?.path || null,
  });
}

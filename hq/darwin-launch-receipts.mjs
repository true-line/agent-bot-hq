// The private stderr stream comes from the supervisor. Adapter stderr is
// always wrapped as a text field and can never supply a lifecycle record.
import { parseStrict } from '../sdk/wire/strict-json.mjs';

export function supervisorReceipts(onStart, adapterStderr) {
  let phase = 'waiting', code = null, partial = '', invalid = false;
  return {
    push(chunk) {
      if (invalid) return;
      const lines = (partial + chunk).split('\n');
      partial = lines.pop();
      if (partial.length > 4096) { invalid = true; return; }
      for (const line of lines) {
        try {
          if (!line || line.length > 4096) throw new Error();
          const record = parseStrict(line, { maxDepth: 2 });
          const keys = Object.keys(record).sort().join(',');
          if (keys === 'kind' && record.kind === 'started' && phase === 'waiting') {
            phase = 'started'; onStart();
          } else if (keys === 'kind,text' && record.kind === 'stderr' && phase === 'started' && typeof record.text === 'string') {
            adapterStderr(record.text);
          } else if (keys === 'exit_code,kind' && record.kind === 'closed' && phase === 'started' &&
              Number.isInteger(record.exit_code) && record.exit_code >= -1 && record.exit_code <= 255) {
            phase = 'closed'; code = record.exit_code;
          } else throw new Error();
        } catch { invalid = true; return; }
      }
    },
    finish(exit, pipesClosed) {
      if (invalid || partial || !pipesClosed || exit?.signal || !exit) return { contained: false };
      if (exit.code === 78 && phase === 'waiting') return { contained: true, refused: true };
      if (exit.code === 0 && phase === 'closed') return { contained: true, code };
      return { contained: false };
    },
  };
}

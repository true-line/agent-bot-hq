// A source stream error does not make pipe() close the destination. Close the
// owner connection so HQ stops its Machine runner instead of leaving ACP live.
export function relaySoulAcp(input, output, socket) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const cleanup = () => {
      input.unpipe(socket);
      socket.unpipe(output);
      input.off('error', onInputError);
      output.off('error', onOutputError);
      socket.off('error', onSocketError);
      socket.off('close', onClose);
    };
    const finish = (message) => {
      if (settled) return;
      settled = true;
      cleanup();
      if (message) { socket.destroy(); reject(new Error(message)); }
      else resolve();
    };
    const onInputError = () => finish('Soul ACP input failed');
    const onOutputError = () => finish('Soul ACP output failed');
    const onSocketError = () => finish('HQ closed the Soul ACP transport after an error');
    const onClose = () => finish();
    input.once('error', onInputError);
    output.once('error', onOutputError);
    socket.once('error', onSocketError);
    socket.once('close', onClose);
    input.pipe(socket);
    socket.pipe(output);
  });
}

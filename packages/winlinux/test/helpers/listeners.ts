// TCP listeners that count connections, for lazy-open tests.
import net from 'node:net';

export interface CountingListener {
  port: number;
  count(): number;
  close(): Promise<void>;
}

// mode 'reset' destroys each socket at once; 'silent' holds it open and never answers.
export async function countingListener(mode: 'reset' | 'silent'): Promise<CountingListener> {
  let connections = 0;
  const sockets = new Set<net.Socket>();
  const server = net.createServer((socket) => {
    connections += 1;
    sockets.add(socket);
    socket.on('close', () => sockets.delete(socket));
    socket.on('error', () => undefined);
    if (mode === 'reset') socket.resetAndDestroy();
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const port = (server.address() as net.AddressInfo).port;
  return {
    port,
    count: () => connections,
    close: async () => {
      for (const socket of sockets) socket.destroy();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

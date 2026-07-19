import { createServer } from 'node:http';

const host = process.env.YUME_COVER_HOST ?? '127.0.0.1';
const port = Number.parseInt(process.env.YUME_COVER_PORT ?? '3000', 10);
if (!Number.isInteger(port) || port < 1 || port > 65535) {
  throw new Error('YUME_COVER_PORT must be 1..65535');
}

const html = Buffer.from(`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Northstar</title><link rel="stylesheet" href="/assets/site.css"></head>
<body><main><h1>Northstar</h1><p>A genuine loopback Node.js site.</p></main>
<script src="/assets/site.js" defer></script></body></html>\n`);
const assets = new Map([
  ['/', ['text/html; charset=utf-8', html]],
  ['/assets/site.css', ['text/css; charset=utf-8', Buffer.from('body{font:16px system-ui;margin:4rem;line-height:1.5}main{max-width:52rem}\n')]],
  ['/assets/site.js', ['text/javascript; charset=utf-8', Buffer.from('document.documentElement.dataset.ready="true";\n')]]
]);

const server = createServer({
  maxHeaderSize: 32 * 1024,
  requestTimeout: 5_000,
  headersTimeout: 5_000,
  keepAliveTimeout: 5_000
}, (req, res) => {
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    const body = Buffer.from('Method Not Allowed\n');
    res.writeHead(405, { 'content-type': 'text/plain; charset=utf-8', 'content-length': body.length });
    return req.method === 'HEAD' ? res.end() : res.end(body);
  }
  const entry = assets.get(req.url);
  const body = entry?.[1] ?? Buffer.from('Not Found\n');
  res.writeHead(entry ? 200 : 404, {
    'content-type': entry?.[0] ?? 'text/plain; charset=utf-8',
    'cache-control': 'public, max-age=60',
    'content-length': body.length
  });
  if (req.method === 'HEAD') res.end(); else res.end(body);
});

server.listen(port, host, () => {
  process.stdout.write(`loopback cover listening on http://${host}:${port}\n`);
});

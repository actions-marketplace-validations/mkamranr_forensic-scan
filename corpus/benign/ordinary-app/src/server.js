const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const STATIC_ROOT = path.join(__dirname, '..', 'public');

function contentTypeFor(filename) {
  const types = { '.html': 'text/html', '.js': 'text/javascript', '.css': 'text/css' };
  return types[path.extname(filename)] || 'application/octet-stream';
}

function serveStatic(req, res) {
  const target = path.join(STATIC_ROOT, path.normalize(req.url).replace(/^(\.\.[/\\])+/, ''));
  fs.readFile(target, (err, data) => {
    if (err) {
      res.writeHead(404);
      res.end('Not found');
      return;
    }
    res.writeHead(200, { 'Content-Type': contentTypeFor(target) });
    res.end(data);
  });
}

http.createServer(serveStatic).listen(PORT, () => {
  console.log(`listening on ${PORT}`);
});

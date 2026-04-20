const http = require("http");

const server = http.createServer((req, res) => {
  res.end("Guardian X is live 🚀");
});

const PORT = process.env.PORT || 3000;
server.listen(PORT);

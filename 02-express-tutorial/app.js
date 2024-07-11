// const http = require("http");
// const { readFileSync } = require("fs");
// // reading the file
// const homePage = readFileSync("./navbar-app/index.html");
// const stylePage = readFileSync("./navbar-app/styles.css");

// const server = http.createServer((req, res) => {
//   if (req.url == "/") {
//     res.writeHead(200, { "content-type": "text/html" });
//     res.write(homePage);
//     res.end();
//   }

//   if (req.url == "/styles.css") {
//     res.writeHead(200, { "content-type": "text/css" });
//     res.write(stylePage);
//     res.end();
//   }

// } else if (req.url == "/about") {
//   res.writeHead(200, { "content-type": "text/html" });
//   res.write("<h1>about</h1>");
//   res.end();
// } else {
//   res.writeHead(404, { "content-type": "text/html" });
//   res.write("<h1>404 not found</h1>");
//   res.end();
// }
// });

// server.listen(5000);

//------------------------------------------------------------------------------------------------//

const express = require("express");
const path = require("path");
const app = express();
const index = path.resolve(__dirname, "./navbar-app/index.html");

app.use(express.static("./public"));

const { products } = require("./data");
const { existsSync } = require("fs");

app.get("/", (req, res) => {
  res.sendFile(index);
});

app.get("/json", (req, res) => {
  res.json(products);
});

app.get("/api/products", (req, res) => {
  const newProducts = products.map((products) => {
    const { id, name, image } = products;
    return { id, name, image };
  });
  console.log(newProducts);
  res.json(newProducts);
});

app.get("/api/products/:id", (req, res) => {
  const id = req.params.id;
  console.log(id);
  const product = products.find((product) => product.id == id);
  if (!product) {
    res.status("404").send("404 product not found");
  }
  res.json(product);
});

app.get("/about", (req, res) => {
  console.log("about page ");
  res.send("about page ");
});

app.all("*", (req, res) => {
  console.log("404");
  res.status(404).send("page not found  ");
});

app.listen(5000, () => {
  console.log("server is running on port 5000");
});

const path = require("path");
const fs = require("fs");
const CopyPlugin = require("copy-webpack-plugin");
const WasmPackPlugin = require("@wasm-tool/wasm-pack-plugin");

const dist = path.resolve(__dirname, "dist");

module.exports = {
  module: {
    rules: [
      {
        test: /\.m?js$/,
        resolve: {
          fullySpecified: false,
        },
      },
    ],
  },
  ignoreWarnings: [
    /Circular dependency between chunks with runtime/,
    /ResizeObserver loop completed with undelivered notifications/,
  ],
  performance: {
    hints: false,
  },
  mode: "production",
  entry: {
    index: "./js/index.js",
  },
  output: {
    path: dist,
    filename: "[name].js",
  },
  devServer: {
    headers: {
      "Cross-Origin-Embedder-Policy": "require-corp",
      "Cross-Origin-Opener-Policy": "same-origin",
    },
    server: {
      type: "https",
      options: {
        key: fs.readFileSync("../src/fixture/mock_server/server-key.pem"),
        cert: fs.readFileSync("../src/fixture/mock_server/server-cert.pem"),
        ca: fs.readFileSync("../src/fixture/mock_server/ca-cert.pem"),
      },
    },
  },
  plugins: [
    new CopyPlugin([path.resolve(__dirname, "static")]),

    // new WasmPackPlugin({
    //   crateDirectory: __dirname,
    //   extraArgs: "--target web"
    // }),
  ],
  experiments: {
    asyncWebAssembly: true,
  },
};

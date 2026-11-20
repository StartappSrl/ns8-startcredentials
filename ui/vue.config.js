module.exports = {
  publicPath: "./",
  // added to fix the build of https://github.com/NethServer/ns8-startcredentials/pull/114
  transpileDependencies: ["axios"],
  configureWebpack: {
    resolve: {
      // webpack 5 non include più i moduli di Node: crypto serve solo per randomBytes
      fallback: { crypto: require.resolve("./src/shims/crypto.js") },
    },
    optimization: {
      splitChunks: {
        // Cap chunk size so the single vendor bundle is split into a few
        // cache-friendly chunks (not one ~2 MiB blob, not dozens of tiny files)
        maxSize: 500000,
      },
    },
  },
  chainWebpack: (config) => {
    // Do not base64 encode images URLs. Needed to always generate module logo image
    // (webpack 5: asset/resource emits the file and returns its URL)
    config.module.rule("images").type("asset/resource");
  },
  css: {
    loaderOptions: {
      sass: {
        sassOptions: {
          silenceDeprecations: [
            "import",
            "global-builtin",
            "color-functions",
            "if-function",
            "legacy-js-api",
          ],
        },
      },
    },
  },
};

// Alcune librerie (kdbxweb, libsodium) chiedono moduli di Node all'avvio ma
// nel browser usano WebCrypto: nel pacchetto li sostituiamo con moduli vuoti.
const NODE_BUILTINS = ["crypto", "fs", "path", "url", "worker_threads"];

export const nodeStubs = {
  name: "node-stubs",
  setup(b) {
    const filter = new RegExp(`^(node:)?(${NODE_BUILTINS.join("|")})$`);
    b.onResolve({ filter }, (args) => ({ path: args.path, namespace: "node-stub" }));
    b.onLoad({ filter: /.*/, namespace: "node-stub" }, () => ({ contents: "module.exports = {};", loader: "js" }));
  },
};

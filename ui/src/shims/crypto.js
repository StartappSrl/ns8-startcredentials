// Sostituto minimo del modulo "crypto" di Node per il browser.
// @nethserver/ns8-ui-lib (tramite uuid) usa solo randomBytes: lo forniamo
// con il generatore sicuro del browser invece di includere crypto-browserify.
export function randomBytes(size) {
  const bytes = new Uint8Array(size);
  window.crypto.getRandomValues(bytes);
  return bytes;
}

export default { randomBytes };

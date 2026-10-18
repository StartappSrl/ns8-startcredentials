// Dopo "expo prebuild": firma la build di release con la chiave aziendale, se
// presente (variabili d'ambiente ANDROID_KEYSTORE_PATH, ANDROID_KEYSTORE_PASSWORD,
// ANDROID_KEY_ALIAS, ANDROID_KEY_PASSWORD). Senza chiave resta la firma di
// prova del modello React Native: va bene solo per i test.
import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const gradle = join(dirname(fileURLToPath(import.meta.url)), "../android/app/build.gradle");
let s = readFileSync(gradle, "utf8");
const ks = process.env.ANDROID_KEYSTORE_PATH;
if (!ks || !existsSync(ks)) {
  console.log("Nessuna chiave aziendale: APK firmato con la chiave di prova (solo per i test).");
  process.exit(0);
}
if (!s.includes("signingConfigs.release")) {
  s = s.replace(/signingConfigs \{\n/, `signingConfigs {
        release {
            storeFile file(System.getenv("ANDROID_KEYSTORE_PATH"))
            storePassword System.getenv("ANDROID_KEYSTORE_PASSWORD")
            keyAlias System.getenv("ANDROID_KEY_ALIAS")
            keyPassword System.getenv("ANDROID_KEY_PASSWORD")
        }
`);
  // Solo il tipo di build "release", dentro buildTypes, passa alla chiave aziendale.
  const types = s.indexOf("buildTypes {");
  const rel = s.indexOf("release {", types);
  const target = s.indexOf("signingConfig signingConfigs.debug", rel);
  if (types < 0 || rel < 0 || target < 0) throw new Error("build.gradle con struttura inattesa: firma non configurata");
  s = s.slice(0, target) + "signingConfig signingConfigs.release" + s.slice(target + "signingConfig signingConfigs.debug".length);
  writeFileSync(gradle, s);
}
console.log("Build di release firmata con la chiave aziendale.");

// Aggiunge al progetto Android l'attività dell'autofill (vedi AutofillActivity.kt).
const fs = require("fs");
const path = require("path");
const { AndroidConfig, withAndroidManifest, withDangerousMod } = require("expo/config-plugins");

function withAutofillActivity(config) {
  config = withAndroidManifest(config, (cfg) => {
    const app = AndroidConfig.Manifest.getMainApplicationOrThrow(cfg.modResults);
    app.activity = app.activity ?? [];
    if (!app.activity.some((a) => a.$["android:name"] === ".AutofillActivity")) {
      app.activity.push({
        $: {
          "android:name": ".AutofillActivity",
          "android:exported": "false",
          "android:theme": "@style/AppTheme",
          "android:launchMode": "standard",
          "android:excludeFromRecents": "true",
          "android:taskAffinity": "",
          "android:windowSoftInputMode": "adjustResize",
          "android:configChanges": "keyboard|keyboardHidden|orientation|screenSize|screenLayout|uiMode",
        },
      });
    }
    return cfg;
  });
  config = withDangerousMod(config, ["android", async (cfg) => {
    const pkg = cfg.android?.package;
    if (!pkg) throw new Error("android.package mancante in app.json");
    const dir = path.join(cfg.modRequest.platformProjectRoot, "app", "src", "main", "java", ...pkg.split("."));
    const src = fs.readFileSync(path.join(__dirname, "AutofillActivity.kt"), "utf8").replaceAll("__PACKAGE__", pkg);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, "AutofillActivity.kt"), src);
    return cfg;
  }]);
  return config;
}

module.exports = withAutofillActivity;

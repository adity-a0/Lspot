# LSpot

An LSPosed module that blocks ads in Spotify by intercepting OkHttp requests to ad endpoints.


## CURRENT SUPPORT VERSION: 9.1.64.1676

## How it works

Hooks `OkHttpClient.Builder.build()` at runtime and injects a dynamic interceptor that returns empty 200 OK responses for ad requests. No APK modification, all in-memory.

## Requirements

- Android 8.1+
- A rooted device with [LSPosed](https://github.com/LSPosed/LSPosed) or any compatible fork

## Install

1. Download the [latest release](https://codeberg.org/dapsvi/LSpot/releases/latest)
2. Install the APK
3. Enable the module in LSPosed/Vector and scope it to `com.spotify.music`
4. Force-stop Spotify and reopen it

## Build from source

In the cloned repo:

```bash
./gradlew assembleRelease
```

Sign with your own keystore:

```bash
apksigner sign --ks your.keystore --ks-key-alias your-alias \
  --out LSpot.apk app/build/outputs/apk/release/app-release-unsigned.apk
```

## Credits

- Originally created by [dapsvi](https://codeberg.org/dapsvi) on Codeberg ([dapsvi/LSpot](https://codeberg.org/dapsvi/LSpot)).
- Official repository: [com.dapsvi.lspot](https://github.com/Xposed-Modules-Repo/com.dapsvi.lspot) on the Xposed Modules Repo.

## License

GPL-3.0

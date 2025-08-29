# Burp Cache-Buster (Java Extension)

A tiny Burp Suite extension that appends a **random cache-busting query parameter** to every HTTP request passing through the Burp Proxy. Example: `?bcb_a8X3fQ=K9mj2r`. Useful for defeating intermediate caches during testing.

## Features

* Adds a random **name** (`bcb_<random>`) and **value** to each proxied request
* Skips `CONNECT` requests and avoids duplicate additions
* Simple UI tab (**Cache Buster**) with an **Enable** checkbox and controls for name/value length

## Requirements

* Burp Suite (Community or Professional)
* JDK 11+ (works with 8+, but 11+ recommended)
* macOS (commands below), Linux/Windows should be similar

## Build (macOS, no Maven)

```bash
# 1) Clone
git clone https://github.com/bitthr3at/burp_ext_cache_burst.git
cd burp_ext_cache_burst

# 2) Set Burp JAR path (adjust if you use Pro)
export BURP_JAR="/Applications/Burp Suite Community Edition.app/Contents/Resources/app/burpsuite_community.jar"

# 3) Compile
mkdir -p out
javac -cp "$BURP_JAR" -d out src/BurpExtender.java

# 4) Package
jar cf CacheBusterExtension.jar -C out .
```

## Install in Burp

1. Open **Burp → Extender → Extensions → Add**
2. Type: **Java**
3. Select: `CacheBusterExtension.jar`
4. Open the **Cache Buster** tab to enable and tweak lengths.

## Notes & Caveats

* Adding query params may break **HMAC-signed** or otherwise **signature-validated** URLs. Disable when testing those flows.
* If you only want this on some hosts, keep the toggle off and selectively enable, or use **Target Scope** + a future host filter.

## License

MIT — see `LICENSE`.

> Burp Suite is a trademark of PortSwigger Ltd. This project is not affiliated with or endorsed by PortSwigger.

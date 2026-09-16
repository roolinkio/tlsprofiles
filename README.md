# Roolink TLS profiles

TLS client profiles that reproduce the handshakes of iOS apps built with Akamai's Bot Manager Premier SDK. Akamai checks the handshake and the HTTP/2 settings before it reads the sensor, so a client that connects with one of these profiles is the other half of a Roolink BMP sensor.

The same six profiles ship in two forms:

- `profiles.go`: a Go module for [bogdanfinn/tls-client](https://github.com/bogdanfinn/tls-client).
- `profiles.json`: custom-client definitions for the tls-client shared library, used from Python ([Python-Tls-Client](https://github.com/Nintendocustom/Python-Tls-Client)) and Node ([tlsclientwrapper](https://www.npmjs.com/package/tlsclientwrapper)).

## The profiles

iOS apps on Akamai's SDK connect with one of two handshake families, **Standard** and **Secondary**. The handshake also changes between iOS releases, so each family has three variants keyed on the `ios` version in the Roolink sensor response.

| `ios` in the response | Standard | Secondary |
| --- | --- | --- |
| 26.2 and later | `StandardIOS26_2` | `SecondaryIOS26_2` |
| 26.0 and 26.1 | `StandardIOS26` | `SecondaryIOS26` |
| Older | `StandardIOS` | `SecondaryIOS` |

Start with Standard. If the app refuses the session although the sensor is fresh and the cookies are set, switch to Secondary. Note which one an app accepts.

| Profile | JA4 | HTTP/2 |
| --- | --- | --- |
| `StandardIOS26_2`, `StandardIOS26` | `t13d1313h2_f57a46bbacb6_7f0f34a4126d` | `2:0;4:2097152;3:100;9:1\|10485760\|0\|m,s,p,a` |
| `SecondaryIOS26_2`, `SecondaryIOS26`, `SecondaryIOS` | `t13d2013h2_a09f3c656075_7f0f34a4126d` | Secondary 26.x: as above. `SecondaryIOS`: `2:0;4:2097152;3:100\|10485760\|0\|m,s,p,a` |
| `StandardIOS` | `t13d1314h2_f57a46bbacb6_e42f34c56612` | `2:0;4:2097152;3:100\|10485760\|0\|m,s,p,a` |

Standard and Secondary differ in cipher-suite order and count (Secondary adds the legacy TLS 1.2 suites), in the TLS versions offered, and in whether a padding extension is present. The 26.x variants add the X25519MLKEM768 key share and the `NO_RFC7540_PRIORITIES` HTTP/2 setting that older iOS releases do not send.

## Go

```go
import (
	tls_client "github.com/bogdanfinn/tls-client"
	"github.com/roolinkio/tlsprofiles"
)

client, err := tls_client.NewHttpClient(tls_client.NewNoopLogger(),
	tls_client.WithClientProfile(tlsprofiles.StandardIOS26_2),
	tls_client.WithCookieJar(tls_client.NewCookieJar()),
	tls_client.WithProxyUrl(proxyURL),
	tls_client.WithDisableHttp3(),
)
```

Built against tls-client v1.16.0 and utls v1.7.8-barnius. Keep the same profile for the life of a session; switching mid-session ends it.

## Python and Node

Each entry of `profiles.json` is one profile with the keys the shared library's `customTlsClient` payload takes:

| Key | What it holds |
| --- | --- |
| `ja3String` | Cipher suites, extensions in order, curves and point formats. GREASE placeholders are `2570`. |
| `supportedSignatureAlgorithms`, `supportedVersions`, `keyShareCurves`, `certCompressionAlgos`, `alpnProtocols` | The extension contents the JA3 string cannot carry. |
| `h2Settings`, `h2SettingsOrder`, `pseudoHeaderOrder`, `connectionFlow` | The HTTP/2 SETTINGS frame, its order, the pseudo-header order and the connection window. `UNKNOWN_SETTING_9` is `NO_RFC7540_PRIORITIES`. |

Node passes an entry straight through as `customTlsClient`, with `withRandomTLSExtensionOrder: false` and `disableHttp3: true`. Python needs a small `Session` subclass because the wrapper's custom-client payload predates the current shared library; the Roolink docs show it in full.

All six JSON profiles are checked against the Go module: identical JA3, JA4 and HTTP/2 fingerprints from Go, Node and Python.

## Verifying a client

Request `https://tls.peet.ws/api/all` through the client and compare `tls.ja4` and `http2.akamai_fingerprint` with the table above. A mismatch means the profile did not apply, usually because extension randomization is on or HTTP/3 is enabled.

Documentation: https://docs.roolink.io

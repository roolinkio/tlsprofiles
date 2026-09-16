// Package tlsprofiles holds the TLS client profiles that reproduce the handshakes
// of iOS apps built with Akamai's Bot Manager Premier SDK, for use with
// github.com/bogdanfinn/tls-client. Two handshake families exist, Standard and
// Secondary, each in three variants keyed on the iOS version reported by the
// Roolink sensor response. profiles.json carries the same six profiles as
// custom-client definitions for the Python and Node wrappers.
package tlsprofiles

import (
	"github.com/bogdanfinn/fhttp/http2"
	"github.com/bogdanfinn/tls-client/profiles"
	tls "github.com/bogdanfinn/utls"
)

var (
	// StandardIOS26_2 is the Standard handshake for iOS 26.2 and later: the first profile to try.
	// JA4 t13d1313h2_f57a46bbacb6_7f0f34a4126d.
	StandardIOS26_2 = profiles.NewClientProfile(
		tls.ClientHelloID{
			Client:               "StandardIOS",
			RandomExtensionOrder: false,
			Version:              "1.0.0",
			Seed:                 nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				clientHello := tls.ClientHelloSpec{
					CipherSuites: []uint16{
						tls.GREASE_PLACEHOLDER,
						0x1302,
						0x1301,
						0x1303,
						0xc02c,
						0xc030,
						0xc02b,
						0xcca9,
						0xc02f,
						0xcca8,
						0xc00a,
						0xc009,
						0xc014,
						0xc013,
					},
					CompressionMethods: []uint8{tls.CompressionNone},
					Extensions: []tls.TLSExtension{
						&tls.UtlsGREASEExtension{},
						&tls.SNIExtension{},
						&tls.ExtendedMasterSecretExtension{},
						&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
						&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
							tls.CurveID(tls.GREASE_PLACEHOLDER),
							0x11ec,
							0x001d,
							0x0017,
							0x0018,
							0x0019,
						}},
						&tls.SupportedPointsExtension{SupportedPoints: []byte{
							tls.PointFormatUncompressed,
						}},
						&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
						&tls.StatusRequestExtension{},
						&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
							0x0403,
							0x0804,
							0x0401,
							0x0503,
							0x0805,
							0x0805,
							0x0501,
							0x0806,
							0x0601,
							0x0201,
						}},
						&tls.SCTExtension{},
						&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
							{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
							{Group: tls.X25519MLKEM768},
							{Group: tls.X25519},
						}},
						&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
							tls.PskModeDHE,
						}},
						&tls.SupportedVersionsExtension{Versions: []uint16{
							tls.GREASE_PLACEHOLDER,
							tls.VersionTLS13,
							tls.VersionTLS12,
						}},
						&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
							tls.CertCompressionZlib,
						}},
						&tls.UtlsGREASEExtension{},
						&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
					},
				}
				return clientHello, nil
			},
			Weights: &tls.Weights{},
		},
		map[http2.SettingID]uint32{
			http2.SettingEnablePush:           0,
			http2.SettingMaxConcurrentStreams: 100,
			http2.SettingInitialWindowSize:    2097152,
			9:                                 1,
		},
		[]http2.SettingID{
			http2.SettingEnablePush,
			http2.SettingInitialWindowSize,
			http2.SettingMaxConcurrentStreams,
			9,
		},
		[]string{
			":method",
			":scheme",
			":path",
			":authority",
		},
		uint32(10485760),
		[]http2.Priority{},
		&http2.PriorityParam{},
		0, false, nil, nil, 0, nil, false,
	)
	// SecondaryIOS26_2 is the Secondary handshake for iOS 26.2 and later: the fallback when Standard is refused.
	// JA4 t13d2013h2_a09f3c656075_7f0f34a4126d.
	SecondaryIOS26_2 = profiles.NewClientProfile(
		tls.ClientHelloID{
			Client:               "SecondaryIOS",
			RandomExtensionOrder: false,
			Version:              "1.0.0",
			Seed:                 nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				return tls.ClientHelloSpec{
					CipherSuites: []uint16{
						tls.GREASE_PLACEHOLDER,
						tls.TLS_AES_256_GCM_SHA384,
						tls.TLS_CHACHA20_POLY1305_SHA256,
						tls.TLS_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
						tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
						tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
						tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
						tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
						tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
						tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_RSA_WITH_AES_256_CBC_SHA,
						tls.TLS_RSA_WITH_AES_128_CBC_SHA,
						tls.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
						tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
						tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
					},
					CompressionMethods: []uint8{
						tls.CompressionNone,
					},
					Extensions: []tls.TLSExtension{
						&tls.UtlsGREASEExtension{},
						&tls.SNIExtension{},
						&tls.ExtendedMasterSecretExtension{},
						&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateNever},
						&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
							tls.CurveID(tls.GREASE_PLACEHOLDER),
							tls.X25519MLKEM768,
							tls.X25519,
							tls.CurveP256,
							tls.CurveP384,
							tls.CurveP521,
						}},
						&tls.SupportedPointsExtension{SupportedPoints: []byte{0x00}},
						&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
						&tls.StatusRequestExtension{},
						&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
							tls.ECDSAWithP256AndSHA256,
							tls.PSSWithSHA256,
							tls.PKCS1WithSHA256,
							tls.ECDSAWithP384AndSHA384,
							tls.PSSWithSHA384,
							tls.PSSWithSHA384,
							tls.PKCS1WithSHA384,
							tls.PSSWithSHA512,
							tls.PKCS1WithSHA512,
							tls.PKCS1WithSHA1,
						}},
						&tls.SCTExtension{},
						&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
							{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0} /* TLS_GREASE (0x6a6a) */},
							{Group: tls.X25519MLKEM768},
							{Group: tls.X25519},
						}},
						&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
							tls.PskModeDHE,
						}},
						&tls.SupportedVersionsExtension{Versions: []uint16{
							tls.GREASE_PLACEHOLDER,
							tls.VersionTLS13,
							tls.VersionTLS12,
							tls.VersionTLS11,
							tls.VersionTLS10,
						}},
						&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
							tls.CertCompressionZlib,
						}},
						&tls.UtlsGREASEExtension{},
					},
				}, nil
			},
		},
		map[http2.SettingID]uint32{
			http2.SettingEnablePush:           0,
			http2.SettingInitialWindowSize:    2097152,
			http2.SettingMaxConcurrentStreams: 100,
			9:                                 1,
		},
		[]http2.SettingID{
			http2.SettingEnablePush,
			http2.SettingInitialWindowSize,
			http2.SettingMaxConcurrentStreams,
			9,
		},
		[]string{
			":method",
			":scheme",
			":path",
			":authority",
		},
		uint32(10485760),
		[]http2.Priority{},
		&http2.PriorityParam{},
		0, false, nil, nil, 0, nil, false,
	)
	// StandardIOS26 is the Standard handshake for iOS 26.0 and 26.1: the first profile to try.
	// JA4 t13d1313h2_f57a46bbacb6_7f0f34a4126d.
	StandardIOS26 = profiles.NewClientProfile(
		tls.ClientHelloID{
			Client:               "StandardIOS",
			RandomExtensionOrder: false,
			Version:              "1.0.0",
			Seed:                 nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				clientHello := tls.ClientHelloSpec{
					CipherSuites: []uint16{
						tls.GREASE_PLACEHOLDER,
						0x1302,
						0x1303,
						0x1301,
						0xc02c,
						0xc02b,
						0xcca9,
						0xc030,
						0xc02f,
						0xcca8,
						0xc00a,
						0xc009,
						0xc014,
						0xc013,
					},
					CompressionMethods: []uint8{tls.CompressionNone},
					Extensions: []tls.TLSExtension{
						&tls.UtlsGREASEExtension{},
						&tls.SNIExtension{},
						&tls.ExtendedMasterSecretExtension{},
						&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
						&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
							tls.CurveID(tls.GREASE_PLACEHOLDER),
							0x11ec,
							0x001d,
							0x0017,
							0x0018,
							0x0019,
						}},
						&tls.SupportedPointsExtension{SupportedPoints: []byte{
							tls.PointFormatUncompressed,
						}},
						&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
						&tls.StatusRequestExtension{},
						&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
							0x0403,
							0x0804,
							0x0401,
							0x0503,
							0x0805,
							0x0805,
							0x0501,
							0x0806,
							0x0601,
							0x0201,
						}},
						&tls.SCTExtension{},
						&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
							{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
							{Group: tls.X25519MLKEM768},
							{Group: tls.X25519},
						}},
						&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
							tls.PskModeDHE,
						}},
						&tls.SupportedVersionsExtension{Versions: []uint16{
							tls.GREASE_PLACEHOLDER,
							tls.VersionTLS13,
							tls.VersionTLS12,
						}},
						&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
							tls.CertCompressionZlib,
						}},
						&tls.UtlsGREASEExtension{},
						&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
					},
				}
				return clientHello, nil
			},
			Weights: &tls.Weights{},
		},
		map[http2.SettingID]uint32{
			http2.SettingEnablePush:           0,
			http2.SettingMaxConcurrentStreams: 100,
			http2.SettingInitialWindowSize:    2097152,
			9:                                 1,
		},
		[]http2.SettingID{
			http2.SettingEnablePush,
			http2.SettingInitialWindowSize,
			http2.SettingMaxConcurrentStreams,
			9,
		},
		[]string{
			":method",
			":scheme",
			":path",
			":authority",
		},
		uint32(10485760),
		[]http2.Priority{},
		&http2.PriorityParam{},
		0, false, nil, nil, 0, nil, false,
	)
	// SecondaryIOS26 is the Secondary handshake for iOS 26.0 and 26.1: the fallback when Standard is refused.
	// JA4 t13d2013h2_a09f3c656075_7f0f34a4126d.
	SecondaryIOS26 = profiles.NewClientProfile(
		tls.ClientHelloID{
			Client:               "SecondaryIOS",
			RandomExtensionOrder: false,
			Version:              "1.0.0",
			Seed:                 nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				return tls.ClientHelloSpec{
					CipherSuites: []uint16{
						tls.GREASE_PLACEHOLDER,
						tls.TLS_AES_256_GCM_SHA384,
						tls.TLS_CHACHA20_POLY1305_SHA256,
						tls.TLS_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
						tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
						tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
						tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
						tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
						tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
						tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
						tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
						tls.TLS_RSA_WITH_AES_256_CBC_SHA,
						tls.TLS_RSA_WITH_AES_128_CBC_SHA,
						tls.TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA,
						tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA,
						tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA,
					},
					CompressionMethods: []uint8{
						tls.CompressionNone,
					},
					Extensions: []tls.TLSExtension{
						&tls.UtlsGREASEExtension{},
						&tls.SNIExtension{},
						&tls.ExtendedMasterSecretExtension{},
						&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateNever},
						&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
							tls.CurveID(tls.GREASE_PLACEHOLDER),
							tls.X25519MLKEM768,
							tls.X25519,
							tls.CurveP256,
							tls.CurveP384,
							tls.CurveP521,
						}},
						&tls.SupportedPointsExtension{SupportedPoints: []byte{0x00}},
						&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
						&tls.StatusRequestExtension{},
						&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
							tls.ECDSAWithP256AndSHA256,
							tls.PSSWithSHA256,
							tls.PKCS1WithSHA256,
							tls.ECDSAWithP384AndSHA384,
							tls.PSSWithSHA384,
							tls.PSSWithSHA384,
							tls.PKCS1WithSHA384,
							tls.PSSWithSHA512,
							tls.PKCS1WithSHA512,
							tls.PKCS1WithSHA1,
						}},
						&tls.SCTExtension{},
						&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
							{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0} /* TLS_GREASE (0x6a6a) */},
							{Group: tls.X25519MLKEM768},
							{Group: tls.X25519},
						}},
						&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
							tls.PskModeDHE,
						}},
						&tls.SupportedVersionsExtension{Versions: []uint16{
							tls.GREASE_PLACEHOLDER,
							tls.VersionTLS13,
							tls.VersionTLS12,
						}},
						&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
							tls.CertCompressionZlib,
						}},
						&tls.UtlsGREASEExtension{},
					},
				}, nil
			},
		},
		map[http2.SettingID]uint32{
			http2.SettingEnablePush:           0,
			http2.SettingInitialWindowSize:    2097152,
			http2.SettingMaxConcurrentStreams: 100,
			9:                                 1,
		},
		[]http2.SettingID{
			http2.SettingEnablePush,
			http2.SettingInitialWindowSize,
			http2.SettingMaxConcurrentStreams,
			9,
		},
		[]string{
			":method",
			":scheme",
			":path",
			":authority",
		},
		uint32(10485760),
		[]http2.Priority{},
		&http2.PriorityParam{},
		0, false, nil, nil, 0, nil, false,
	)
	// StandardIOS is the Standard handshake for iOS releases before 26: the first profile to try.
	// JA4 t13d1314h2_f57a46bbacb6_e42f34c56612.
	StandardIOS = profiles.NewClientProfile(
		tls.ClientHelloID{
			Client:               "StandardIOS",
			RandomExtensionOrder: false,
			Version:              "1.0.0",
			Seed:                 nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				clientHello := tls.ClientHelloSpec{
					CipherSuites: []uint16{
						tls.GREASE_PLACEHOLDER,
						0x1301,
						0x1302,
						0x1303,
						0xc02c,
						0xc02b,
						0xcca9,
						0xc030,
						0xc02f,
						0xcca8,
						0xc00a,
						0xc009,
						0xc014,
						0xc013,
					},
					CompressionMethods: []uint8{tls.CompressionNone},
					Extensions: []tls.TLSExtension{
						&tls.UtlsGREASEExtension{},
						&tls.SNIExtension{},
						&tls.ExtendedMasterSecretExtension{},
						&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateNever},
						&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
							tls.CurveID(tls.GREASE_PLACEHOLDER),
							tls.X25519,
							tls.CurveP256,
							tls.CurveP384,
							tls.CurveP521,
						}},
						&tls.SupportedPointsExtension{SupportedPoints: []byte{0}},
						&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
						&tls.StatusRequestExtension{},
						&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
							tls.ECDSAWithP256AndSHA256,
							tls.PSSWithSHA256,
							tls.PKCS1WithSHA256,
							tls.ECDSAWithP384AndSHA384,
							tls.PSSWithSHA384,
							tls.PSSWithSHA384,
							tls.PKCS1WithSHA384,
							tls.PSSWithSHA512,
							tls.PKCS1WithSHA512,
							tls.PKCS1WithSHA1,
						}},
						&tls.SCTExtension{},
						&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
							{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
							{Group: tls.X25519},
						}},
						&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
							tls.PskModeDHE,
						}},
						&tls.SupportedVersionsExtension{Versions: []uint16{
							tls.GREASE_PLACEHOLDER,
							tls.VersionTLS13,
							tls.VersionTLS12,
						}},
						&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
							tls.CertCompressionZlib,
						}},
						&tls.UtlsGREASEExtension{},
						&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle},
					},
				}
				return clientHello, nil
			},
			Weights: &tls.Weights{},
		},
		map[http2.SettingID]uint32{
			http2.SettingEnablePush:           0,
			http2.SettingInitialWindowSize:    2097152,
			http2.SettingMaxConcurrentStreams: 100,
		},
		[]http2.SettingID{
			http2.SettingEnablePush,
			http2.SettingInitialWindowSize,
			http2.SettingMaxConcurrentStreams,
		},
		[]string{
			":method",
			":scheme",
			":path",
			":authority",
		},
		uint32(10485760),
		[]http2.Priority{},
		&http2.PriorityParam{},
		0, false, nil, nil, 0, nil, false,
	)
	// SecondaryIOS is the Secondary handshake for iOS releases before 26: the fallback when Standard is refused.
	// JA4 t13d2013h2_a09f3c656075_7f0f34a4126d.
	SecondaryIOS = profiles.NewClientProfile(
		tls.ClientHelloID{
			Client:               "SecondaryIOS",
			RandomExtensionOrder: false,
			Version:              "1.0.0",
			Seed:                 nil,
			SpecFactory: func() (tls.ClientHelloSpec, error) {
				clientHello := tls.ClientHelloSpec{
					CipherSuites: []uint16{
						tls.GREASE_PLACEHOLDER,
						0x1301,
						0x1302,
						0x1303,
						0xc02c,
						0xc02b,
						0xcca9,
						0xc030,
						0xc02f,
						0xcca8,
						0xc00a,
						0xc009,
						0xc014,
						0xc013,
						0x9d,
						0x9c,
						0x35,
						0x2f,
						0xc008,
						0xc012,
						0xa,
					},
					CompressionMethods: []uint8{tls.CompressionNone},
					Extensions: []tls.TLSExtension{
						&tls.UtlsGREASEExtension{},
						&tls.SNIExtension{},
						&tls.ExtendedMasterSecretExtension{},
						&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
						&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
							tls.CurveID(tls.GREASE_PLACEHOLDER),
							tls.X25519,
							tls.CurveP256,
							tls.CurveP384,
							tls.CurveP521,
						}},
						&tls.SupportedPointsExtension{SupportedPoints: []byte{
							tls.PointFormatUncompressed,
						}},
						&tls.ALPNExtension{AlpnProtocols: []string{"h2", "http/1.1"}},
						&tls.StatusRequestExtension{},
						&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
							tls.ECDSAWithP256AndSHA256,
							tls.PSSWithSHA256,
							tls.PKCS1WithSHA256,
							tls.ECDSAWithP384AndSHA384,
							tls.PSSWithSHA384,
							tls.PSSWithSHA384,
							tls.PKCS1WithSHA384,
							tls.PSSWithSHA512,
							tls.PKCS1WithSHA512,
							tls.PKCS1WithSHA1,
						}},
						&tls.SCTExtension{},
						&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
							{Group: tls.CurveID(tls.GREASE_PLACEHOLDER), Data: []byte{0}},
							{Group: tls.X25519},
						}},
						&tls.PSKKeyExchangeModesExtension{Modes: []uint8{
							tls.PskModeDHE,
						}},
						&tls.SupportedVersionsExtension{Versions: []uint16{
							tls.GREASE_PLACEHOLDER,
							tls.VersionTLS13,
							tls.VersionTLS12,
							tls.VersionTLS11,
							tls.VersionTLS10,
						}},
						&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{
							tls.CertCompressionZlib,
						}},
						&tls.UtlsGREASEExtension{},
					},
				}
				return clientHello, nil
			},
		},
		map[http2.SettingID]uint32{
			http2.SettingEnablePush:           0,
			http2.SettingInitialWindowSize:    2097152,
			http2.SettingMaxConcurrentStreams: 100,
		},
		[]http2.SettingID{
			http2.SettingEnablePush,
			http2.SettingInitialWindowSize,
			http2.SettingMaxConcurrentStreams,
		},
		[]string{
			":method",
			":scheme",
			":path",
			":authority",
		},
		uint32(10485760),
		[]http2.Priority{},
		&http2.PriorityParam{},
		0, false, nil, nil, 0, nil, false,
	)
)

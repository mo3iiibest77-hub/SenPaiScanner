package xraytest

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
)

// DefaultCipherSuites is the confirmed production TLS cipher suite list.
// Used whenever a VLESSConfig does not specify its own CipherSuites.
const DefaultCipherSuites = "TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"

// DefaultFingerprint is the confirmed production TLS fingerprint.
// Used whenever a VLESSConfig does not specify its own Fingerprint.
const DefaultFingerprint = "unsafe"

// BuildXrayConfig generates a minimal xray-core JSON config from a VLESSConfig.
// It creates a SOCKS inbound on the given port and a VLESS outbound.
func BuildXrayConfig(cfg *VLESSConfig, socksPort int) ([]byte, error) {
	config := map[string]interface{}{
		"log": map[string]interface{}{
			"loglevel": "none",
			"access":   "",
			"error":    "",
		},
		"dns": map[string]interface{}{
			// Prefer the OS resolver first — on cellular, direct UDP to 1.1.1.1
			// is often blocked while system DNS still works.
			"servers": []interface{}{
				"localhost",
				"1.1.1.1",
				"8.8.8.8",
			},
		},
		"inbounds": []map[string]interface{}{
			{
				"tag":      "socks-in",
				"port":     socksPort,
				"listen":   "127.0.0.1",
				"protocol": "socks",
				// Sniffing overrides the SOCKS destination with sniffed domains and
				// breaks IP-based CF endpoint tests — keep disabled for validation.
				"sniffing": map[string]interface{}{
					"enabled": false,
				},
				"settings": map[string]interface{}{
					"udp": true,
				},
			},
		},
		"outbounds": []map[string]interface{}{
			buildOutbound(cfg),
			{
				"tag":      "direct",
				"protocol": "freedom",
				"settings": map[string]interface{}{},
			},
		},
		"routing": map[string]interface{}{
			"domainStrategy": "AsIs",
			"rules": []map[string]interface{}{
				{
					"type":        "field",
					"outboundTag": "proxy",
					"network":     "tcp,udp",
				},
			},
		},
	}
	return json.MarshalIndent(config, "", "  ")
}

func buildOutbound(cfg *VLESSConfig) map[string]interface{} {
	switch cfg.Protocol {
	case "trojan":
		return buildTrojanOutbound(cfg)
	case "vmess":
		return buildVMessOutbound(cfg)
	default:
		return buildVLESSOutbound(cfg)
	}
}

func buildVMessOutbound(cfg *VLESSConfig) map[string]interface{} {
	return map[string]interface{}{
		"tag":      "proxy",
		"protocol": "vmess",
		"settings": map[string]interface{}{
			"vnext": []map[string]interface{}{
				{
					"address": cfg.Address,
					"port":    cfg.Port,
					"users": []map[string]interface{}{
						{
							"id":       cfg.UUID,
							"alterId":  0,
							"security": "auto",
						},
					},
				},
			},
		},
		"streamSettings": buildStreamSettings(cfg),
	}
}

func buildVLESSOutbound(cfg *VLESSConfig) map[string]interface{} {
	users := []map[string]interface{}{
		{
			"id":         cfg.UUID,
			"encryption": cfg.Encryption,
		},
	}
	if cfg.Flow != "" {
		users[0]["flow"] = cfg.Flow
	}
	return map[string]interface{}{
		"tag":      "proxy",
		"protocol": "vless",
		"settings": map[string]interface{}{
			"vnext": []map[string]interface{}{
				{
					"address": cfg.Address,
					"port":    cfg.Port,
					"users":   users,
				},
			},
		},
		"streamSettings": buildStreamSettings(cfg),
	}
}

func buildTrojanOutbound(cfg *VLESSConfig) map[string]interface{} {
	return map[string]interface{}{
		"tag":      "proxy",
		"protocol": "trojan",
		"settings": map[string]interface{}{
			"servers": []map[string]interface{}{
				{
					"address":  cfg.Address,
					"port":     cfg.Port,
					"password": cfg.Password,
				},
			},
		},
		"streamSettings": buildStreamSettings(cfg),
	}
}

func buildStreamSettings(cfg *VLESSConfig) map[string]interface{} {
	stream := map[string]interface{}{
		"network":  cfg.Network,
		"security": cfg.Security,
	}
	// TLS settings
	if cfg.Security == "tls" {
		tls := map[string]interface{}{}
		if cfg.SNI != "" {
			tls["serverName"] = cfg.SNI
		}
		// Fingerprint always defaults to the confirmed production value
		// ("unsafe") unless the config explicitly overrides it.
		fp := cfg.Fingerprint
		if fp == "" {
			fp = DefaultFingerprint
		}
		tls["fingerprint"] = fp
		// cipherSuites always defaults to the confirmed production list
		// unless the config explicitly overrides it.
		cs := cfg.CipherSuites
		if cs == "" {
			cs = DefaultCipherSuites
		}
		tls["cipherSuites"] = cs
		// allowInsecure was removed from xray-core after 2026-06-01. When dialing
		// a literal IP, xray expects verifyPeerCertByName instead.
		if net.ParseIP(cfg.Address) != nil {
			if vcn := peerCertNames(cfg); vcn != "" {
				tls["verifyPeerCertByName"] = vcn
			}
		}
		if len(cfg.ALPN) > 0 {
			tls["alpn"] = cfg.ALPN
		}
		stream["tlsSettings"] = tls
	}
	// Transport settings
	switch cfg.Network {
	case "ws":
		ws := map[string]interface{}{
			"path": cfg.Path,
		}
		// xray-core expects headers as a map, not a top-level "host" field.
		// Using the correct format ensures the Host header reaches the CDN origin.
		if cfg.Host != "" {
			ws["headers"] = map[string]interface{}{
				"Host": cfg.Host,
			}
		}
		stream["wsSettings"] = ws
	case "grpc":
		grpc := map[string]interface{}{
			"serviceName": cfg.ServiceName,
		}
		if cfg.Authority != "" {
			grpc["authority"] = cfg.Authority
		}
		if cfg.Mode == "multi" {
			grpc["multiMode"] = true
		}
		stream["grpcSettings"] = grpc
	case "xhttp", "splithttp":
		xhttp := map[string]interface{}{
			"path": cfg.Path,
		}
		if cfg.Host != "" {
			xhttp["headers"] = map[string]interface{}{
				"Host": cfg.Host,
			}
		}
		if cfg.Mode != "" {
			xhttp["mode"] = cfg.Mode
		}
		stream["xhttpSettings"] = xhttp
	}
	// Fragment/obfuscation layer ("finalmask" in the production config).
	// Applied by default; set cfg.DisableFragment to skip it.
	if !cfg.DisableFragment {
		stream["finalmask"] = defaultFragmentSettings()
	}
	return stream
}

// defaultFragmentSettings returns the confirmed production fragment
// ("finalmask") layer: two TCP fragment stages that split the TLS
// ClientHello and follow-up packets to evade DPI.
func defaultFragmentSettings() map[string]interface{} {
	return map[string]interface{}{
		"tcp": []map[string]interface{}{
			{
				"type": "fragment",
				"settings": map[string]interface{}{
					"packets":  "tlshello",
					"lengths":  []string{"5", "94", "1"},
					"delays":   []string{"0"},
					"maxSplit": "0",
				},
			},
			{
				"type": "fragment",
				"settings": map[string]interface{}{
					"packets":  "1-1",
					"lengths":  []string{"109", "1"},
					"delays":   []string{"1"},
					"maxSplit": "355",
				},
			},
		},
	}
}

func peerCertNames(cfg *VLESSConfig) string {
	if cfg == nil {
		return ""
	}
	seen := make(map[string]struct{})
	var names []string
	add := func(n string) {
		n = strings.TrimSpace(n)
		if n == "" {
			return
		}
		key := strings.ToLower(n)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		names = append(names, n)
	}
	add(cfg.Host)
	add(cfg.SNI)
	return strings.Join(names, ",")
}

// BuildXrayConfigJSON is a convenience that returns the config as a formatted string.
func BuildXrayConfigJSON(cfg *VLESSConfig, socksPort int) (string, error) {
	b, err := BuildXrayConfig(cfg, socksPort)
	if err != nil {
		return "", fmt.Errorf("building xray config: %w", err)
	}
	return string(b), nil
}

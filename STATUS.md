# PROJECT STATUS

Last updated: 2026-08-18

Repository Layout
Working directory: /opt/quietstorm-vpn/
Repositories:
- pattng/ — PattNG client repository
- senpai-scanner/ — Fork of MatinSenPai/SenPaiScanner
- quietstorm-vpn-docs/ — Separate documentation repository
Scanner remote: https://github.com/mo3iiibest77-hub/SenPaiScanner.git

Confirmed Scanner Architecture
internal/xraytest — Production Validation Layer
The scanner contains a real Xray-core validation layer with:
- Parser (parser.go): Parses VLESS, Trojan, and VMess share links; supports endpoint replacement through WithEndpoint(); includes Phase2SanityError() for detecting bad WS paths
- Builder (builder.go): Builds real Xray-core outbound configurations with VLESS, Trojan, and VMess transports (WS, gRPC, XHTTP)
- Runner (runner.go): Spins up Xray-core instance, waits for local SOCKS listener, performs real traffic validation including connection establishment, /cdn-cgi/trace validation (requires colo= in body), download throughput measurement, optional upload throughput, and one automatic retry on failure
Production TLS/Transport Fields Added (2026-08-17):
- CipherSuites — custom cipher suite list
- DisableFragment — toggle for fragment/finalmask layer
- DefaultFingerprint — "unsafe"
- DefaultCipherSuites — production cipher suite list
- defaultFragmentSettings() — production fragment/finalmask configuration

internal/prober — Screening Layer
Supports TCP, TLS, and HTTP probe modes, SNI rotation across known Cloudflare hostnames, Cloudflare colo detection via CF-Ray and trace body, optional WebSocket probing (idle-hold + upgrade check), and stability idle-hold check (Iran DPI-specific: catches connections that initially succeed but are later reset)

internal/engine — Orchestration Layer
Worker-pool pattern with Run for streaming IPs and RunList for fixed lists (raised timeout floor). No rewrite of the worker architecture is currently required.

Production Transport Configuration
Protocol: VLESS
Transport: WebSocket
Security: TLS
SNI: dnflear.dontbedumb.ir
WebSocket Host: cdnflear.dontbedumb.ir
WebSocket Path: /
ALPN: http/1.1
Fingerprint: unsafe
Custom Cipher Suites: Enabled
Fragment/finalmask: Enabled
Critical: This is NOT Reality. These production values must remain unchanged unless real client testing demonstrates a necessary modification.

Production Fragment/finalmask Settings
TCP Fragment 1:
{
  "type": "fragment",
  "settings": {
    "packets": "tlshello",
    "lengths": ["5", "94", "1"],
    "delays": ["0"],
    "maxSplit": "0"
  }
}
TCP Fragment 2:
{
  "type": "fragment",
  "settings": {
    "packets": "1-1",
    "lengths": ["109", "1"],
    "delays": ["1"],
    "maxSplit": "355"
  }
}

Production Cipher Suites
TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256

E2E Xray Validation Results — 2026-08-18
Test Configuration
Endpoint: 104.18.152.44:2096
Protocol: VLESS
Transport: WebSocket
Security: TLS
SNI: dnflear.dontbedumb.ir
WebSocket Host: cdnflear.dontbedumb.ir
WebSocket Path: /
ALPN: http/1.1
Fingerprint: unsafe
Fragment/finalmask: Production values (unchanged)
Cipher Suites: Production values (unchanged)
Upload Test: Disabled

Initial Issue & Resolution
Issue: Initial test failed with "failed to build mask with type fragment > LengthMin can't be 0"
Root Cause: Xray-core version incompatibility, not production configuration error
Resolution: Updated Xray-core from v1.260327.0 to v1.260327.1-0.20260728075948-5ca6f4b7d4dc
Result: Production fragment values work correctly with updated Xray-core

Five Consecutive E2E Tests
Test 1: Success ✅ | Throughput: ~328 KB/s | Bytes: 524,288 | Retries: 0
Test 2: Success ✅ | Throughput: ~276 KB/s | Bytes: 524,288 | Retries: 0
Test 3: Success ✅ | Throughput: ~297 KB/s | Bytes: 524,288 | Retries: 0
Test 4: Success ✅ | Throughput: ~55 KB/s | Bytes: 524,288 | Retries: 0
Test 5: Success ✅ | Throughput: ~252 KB/s | Bytes: 524,288 | Retries: 0
All five tests succeeded.

Full Test Suite
Command: go test -ldflags='-checklinkname=0' ./... -count=1
Result: All tests passed
Packages tested: internal/export ✅, internal/ipsrc ✅, internal/prober ✅, internal/result ✅, internal/ui ✅, internal/xraytest ✅, desktop ✅

Important Distinction
Scanner E2E: Validates scanner can construct/execute production Xray config — ✅ Confirmed working
Real Client: Validates behavior through actual client/ISP path — ✅ Confirmed working via PattNG
ISP-Specific: Validates reliability from target ISP — ⚠️ Must be measured per ISP
Critical: A successful test on one ISP must NOT automatically be treated as proof for another ISP. ISP-specific reliability must be measured from the target ISP itself.

Git History
c8bbee7 feat(xraytest): apply production fragment/cipherSuites/fingerprint defaults to TLS validation config
5e18d57 fix: update xray-core for fragment mask compatibility
b50156f docs: record Xray E2E validation results

Current State — ✅ Production-Ready Validation Layer
- Production configuration compatibility resolved
- Production fragment values remain unchanged
- Production cipher suites remain unchanged
- Production fingerprint remains unsafe
- Xray E2E validation working with real traffic
- Five consecutive successful tests against production endpoint
- Complete Go test suite passed

Remaining Work
Scanner-Side (Next Phase):
- Candidate scoring/ranking logic
- Combining prober.Result with xraytest.ValidationResult
- Result persistence layer
- CLI integration for Xray validation stage
Client-Side Integration (Future Phase):
- Deep PattNG integration analysis
- How validated candidates are consumed by PattNG configuration management
- SubscriptionUpdater integration
- AngConfigManager integration
- Android/gomobile bridge confirmation

Engineering Directives
1. Preserve production values — Do not change TLS, WebSocket, fingerprint, cipher-suites, or fragment/finalmask values unless real client testing demonstrates a change is required
2. Do not skip ahead — Scoring/ranking and PattNG integration must wait until E2E validation is solid
3. Test from target ISPs — ISP-specific validation must be performed from actual target networks
4. Separate concerns — Scanner validation and client validation serve different purposes; both are valuable
5. Extend, don't rewrite — Existing architecture is sound; focus on adding missing components (scoring, persistence, CLI integration)

This status log is updated when the codebase changes. Read PROJECT_FOUNDATION.md for unchanging rules and architecture.

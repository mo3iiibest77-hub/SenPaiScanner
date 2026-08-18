# PROJECT STATUS — Read After PROJECT_FOUNDATION.md

> This file tracks where the project actually stands right now. Update it
> at the end of any work session (human or AI) that changes what's true
> about the codebase. Keep entries factual and dated — this is a status
> log, not a plan. Read `PROJECT_FOUNDATION.md` first for the unchanging
> rules and architecture; this file tells you what's been confirmed,
> what's missing, and what to do next.

---

## Last updated: 2026-08-17

## Repo layout (confirmed on server, /opt/quietstorm-vpn)
/opt/quietstorm-vpn/
  pattng/          — clone of patterniha/PattNG, checked out at tag 2.3.4-P22
                     (detached HEAD — no local branch created yet)
  senpai-scanner/  — clone of MatinSenPai/SenPaiScanner, main @ v1.0.0
                     origin remote changed 2026-08-17 to point at the fork
                     github.com/mo3iiibest77-hub/SenPaiScanner (write access
                     needed to push commits — the upstream MatinSenPai repo
                     is read-only to this account). Fork pushed at commit
                     c8bbee7 on main.

Both `pattng/` and `senpai-scanner/` are separate git repos from the docs
repo (`quietstorm-vpn-docs`), as intended — see PROJECT_FOUNDATION.md for
the reasoning against merging them.

---

## Confirmed facts about the codebase (verified by reading actual files, not assumed)

### senpai-scanner/internal/xraytest — real Xray validation layer EXISTS

- `parser.go`: parses `vless://` / `trojan://` / `vmess://` share links into
  `VLESSConfig`. Has `WithAddress()` / `WithEndpoint()` for swapping in a
  candidate IP without touching the rest of the profile. Has
  `Phase2SanityError()` for catching bad WS paths. Now also has
  `CipherSuites` and `DisableFragment` fields (added 2026-08-17, see below).
- `builder.go`: builds a real xray-core JSON config from `VLESSConfig`
  (SOCKS inbound + vless/trojan/vmess outbound, ws/grpc/xhttp transports).
  Updated 2026-08-17 — see "DONE" items below. No longer missing the
  fragment/cipherSuites/fingerprint layer.
- `runner.go`: actually spins up an `xcore.Instance`, waits for the local
  SOCKS port, and validates through real traffic — connectivity check via
  `/cdn-cgi/trace` (requires `colo=` in body), download throughput, optional
  upload throughput, one automatic retry on failure. `ProxyConnectivityCheck`
  is exported "for the Android gomobile bridge" — not yet confirmed whether
  that bridge actually exists on the PattNG side.

### senpai-scanner/internal/prober — screening layer EXISTS

- TCP / TLS / HTTP probe modes, SNI rotation across known Cloudflare
  hostnames, colo detection via CF-Ray and trace body, optional WebSocket
  probe (idle-hold + upgrade check to detect DPI killing long-lived TLS),
  optional "stability" idle-hold check after a successful HTTP probe (Iran
  DPI-specific: catches DPI that allows the initial GET but RSTs shortly
  after).

### senpai-scanner/internal/engine — orchestration EXISTS

- Standard worker-pool pattern (`Run` for streaming IPs, `RunList` for fixed
  lists with a raised timeout floor). Nothing unusual; extend, don't
  rewrite.

### NOT yet found / not yet confirmed

- No scoring/ranking logic located yet.
- No code combining a `prober.Result` (screening) with a
  `xraytest.ValidationResult` (real validation) into one final decision.
- No result persistence layer located yet.
- No CLI subcommand wiring for the xraytest layer located yet (need to check
  `cmd/`).
- PattNG-side Xray/subscription integration not yet inspected (need to look
  at `AngConfigManager`, `V2rayConfig`, `SubscriptionUpdater`, etc.)
- Whether a gomobile bridge already exists on the PattNG/Android side to
  call `ProxyConnectivityCheck` — unconfirmed.

---

## CONFIRMED CORRECTION: production transport is TLS+WS+fragment, not Reality

Earlier working assumption (now retracted) was that this project targets
Reality. The user provided the actual production subscription config and
confirmed:

- Transport: `security: tls`, `network: ws` — not `reality`.
- A fragment/obfuscation layer (called `finalmask` in the real config,
  `type: fragment`) that splits the TLS ClientHello and follow-up packets
  per specific `delays` / `lengths` / `maxSplit` values, to evade DPI.
- A custom, specific `cipherSuites` list (not the Go/xray default).
- `fingerprint: "unsafe"`.

Default fragment (`finalmask`, applied under `streamSettings`, alongside
`tlsSettings`, as a `tcp` array with two fragment entries):

"finalmask": {
  "tcp": [
    {
      "type": "fragment",
      "settings": {
        "packets": "tlshello",
        "lengths": ["5", "94", "1"],
        "delays": ["0"],
        "maxSplit": "0"
      }
    },
    {
      "type": "fragment",
      "settings": {
        "packets": "1-1",
        "lengths": ["109", "1"],
        "delays": ["1"],
        "maxSplit": "355"
      }
    }
  ]
}

Default `cipherSuites` (single colon-joined string, under `tlsSettings`):

TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256

Default `fingerprint` (under `tlsSettings`): unsafe

---

## NEXT STEPS (in order)

1. DONE (2026-08-17): `buildStreamSettings` now defaults `fingerprint` to
   `DefaultFingerprint` ("unsafe") whenever `cfg.Fingerprint` is empty,
   regardless of what parsing produced.
2. DONE (2026-08-17): `internal/xraytest/parser.go` gained two new
   `VLESSConfig` fields (`CipherSuites`, `DisableFragment`).
   `internal/xraytest/builder.go` was rewritten: `buildStreamSettings` now
   injects `DefaultCipherSuites` and `DefaultFingerprint` when the config
   doesn't override them, and appends the `finalmask` fragment layer
   (`defaultFragmentSettings()`) unless `cfg.DisableFragment` is true.
   Verified with `go build ./...` (Go 1.26.1 installed manually — the
   apt-provided `golang-go` 1.18 is too old for this module, which
   requires `go 1.26.1` per `go.mod`) — build succeeded with no errors.
   Committed to the `senpai-scanner` repo (not the docs repo).
3. OPEN — next step: re-verify end to end. Build a VLESSConfig from a real
   subscription entry, swap in a scanner-confirmed candidate IP, run it
   through `ValidateConfig`, confirm it reports success against the real
   DPI environment (Iranian ISP), not just from the scanner server. A
   successful compile only proves the code is well-typed, not that it
   produces a working tunnel against real DPI — this has NOT been tested
   yet.
4. Only after step 3 works reliably: start on scoring/ranking and result
   persistence.
5. Only after the scanner side is solid: move to PattNG-side integration
   (how the client receives/uses scanner-validated candidate lists).

Do not skip ahead to scoring, PattNG integration, or branding work before
step 3 is done — an unrepresentative validation layer makes everything
built on top of it unreliable.

## Environment note

Go 1.26.1 was installed manually under `/usr/local/go` on the build server
via the official tarball, with `PATH` updated in `~/.bashrc`. The distro's
`apt` Go package (1.18) is too old for this project (go.mod requires
`go 1.26.1`).


---

## E2E VALIDATION RESULT — 2026-08-18

The previously open end-to-end validation step was completed successfully.

### Test target

A real production VLESS configuration was used:

- Protocol: VLESS
- Transport: WebSocket
- Security: TLS
- Candidate endpoint: `104.18.152.44:2096`
- SNI: `dnflear.dontbedumb.ir`
- WebSocket Host: `cdnflear.dontbedumb.ir`
- WebSocket Path: `/`
- ALPN: `http/1.1`
- TLS fingerprint: `unsafe`
- Production `finalmask` / fragment layer: enabled
- Production custom cipher suite list: enabled
- Upload test: disabled for this validation

The candidate IP was swapped into the parsed production profile using `WithEndpoint()`. The test therefore exercised the real Xray validation path rather than a generic TCP/TLS probe.

### Important Xray-core compatibility finding

The first E2E attempt failed before any network connection because the installed Xray-core version rejected the production fragment configuration:

`failed to build mask with type fragment > LengthMin can't be 0`

The failure was caused by the older Xray-core dependency rejecting the production fragment representation.

A temporary attempt to convert the production fragment lengths from exact values such as `5`, `94`, `1` into range notation such as `5-5`, `94-94`, `1-1` was tested and correctly rejected as unsuitable. The production fragment values themselves were not changed.

The correct fix was to update the SenPaiScanner Xray-core dependency from:

`github.com/xtls/xray-core v1.260327.0`

to:

`github.com/xtls/xray-core v1.260327.1-0.20260728075948-5ca6f4b7d4dc`

After the dependency update, the original production fragment values were restored unchanged.

### Production fragment values preserved

The scanner now uses the actual production fragment configuration:

```json
{
  "tcp": [
    {
      "type": "fragment",
      "settings": {
        "packets": "tlshello",
        "lengths": ["5", "94", "1"],
        "delays": ["0"],
        "maxSplit": "0"
      }
    },
    {
      "type": "fragment",
      "settings": {
        "packets": "1-1",
        "lengths": ["109", "1"],
        "delays": ["1"],
        "maxSplit": "355"
      }
    }
  ]
}

The production custom cipher suite list and fingerprint: "unsafe" are also applied by internal/xraytest/builder.go.
### E2E result
After the Xray-core update, the exact same production configuration and candidate IP were tested five consecutive times.
All five tests succeeded.
Observed results:
Test 1: success, approximately 328 KB/s
Test 2: success, approximately 276 KB/s
Test 3: success, approximately 297 KB/s
Test 4: success, approximately 55 KB/s
Test 5: success, approximately 252 KB/s
Bytes received in every successful test: 524288
Upload testing: disabled
Xray retries: 0 on all five successful runs
No Xray configuration/build errors remained
This establishes that the scanner's ValidateConfig() path can successfully start Xray-core and pass real traffic through the production VLESS + TLS + WS + fragment + cipher-suite + unsafe-fingerprint configuration.
This is a real end-to-end validation from the test environment, not merely compilation or a TCP/TLS probe.
It does NOT establish universal usability across all ISPs or networks. Client-network validation remains a separate concern and must be measured from the actual restricted user network when evaluating ISP-specific behavior.
## Full repository verification
After the Xray-core update:
go test -ldflags='-checklinkname=0' ./... -count=1
completed successfully for the entire SenPaiScanner repository.
All existing test packages passed, including:
internal/export
internal/ipsrc
internal/prober
internal/result
internal/ui
internal/xraytest
No test package reported a failure.
The temporary .e2e-baseline test harness was removed after validation.
## Git state
The successful Xray-core dependency update was committed and pushed to:
github.com/mo3iiibest77-hub/SenPaiScanner
The fork's main branch now contains the completed dependency update and the associated go.sum changes.
## Current conclusion
The previously identified xraytest production-configuration gap is now closed and the resulting validation path has been exercised successfully against a real production VLESS endpoint.
The scanner is therefore ready for the next project phase.
The next engineering step remains scoring/ranking and result persistence, followed by eventual PattNG-side integration. Do not treat the current five successful runs as proof that every Cloudflare candidate or every ISP will work; the validation layer is now proven functional, while broader network/ISP coverage still requires representative client-side testing.

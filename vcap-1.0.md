# vLEI Key Authenticator Protocol (VCAP) 1.0

**Status:** Review Draft

**Scope:** Authenticator firmware, and the parts of wallets, enterprise Ticket issuers and manufacturing tools that interact directly with the authenticator.

**Abstract:** This document defines the protocol between a vLEI Key authenticator and a platform: the transport, the command set, the processing steps the authenticator performs for each command, data structures and status codes, and the procedures that wallets and enterprises follow when using the authenticator.

---

## Contents

1. Introduction
2. Conformance
3. Terminology and Notation
4. Protocol Overview
5. Authenticator State Model
6. Encoding, Identifiers and Cryptographic Primitives
7. Authenticator API
8. Common Authenticator Procedures
9. Data Structures
10. Status Codes
11. Transport Bindings
12. Platform and Enterprise Procedures
13. Security Considerations
- Appendix A Constants
- Appendix B Role Capability Bits
- Appendix C References

---

## 1. Introduction

### 1.1 Purpose

The vLEI Key is a personal KERI signing device with a touch sensor. An employee's KERI private keys exist only inside the authenticator.

Because both the platform running the wallet and the enterprise services may be compromised, the following five rules are enforced by the authenticator itself:

1. **Private keys stay in the authenticator.** The PIN failure count is kept in the authenticator and survives power loss. Every signature requires one deliberate user action (user presence, UP): a press of the touch sensor, or over NFC the tap that brings the authenticator into the reader's field.
2. **Every signature is authorized by the enterprise.** Each signature requires a Ticket issued by an enterprise role key. The Ticket specifies the context, the signing key, and the digest and length of the message to be signed.
3. **Rotation stays within authenticator-generated keys.** The current key and next key in `icp` MUST be two keys generated inside the authenticator. A `rot` MUST be signed with the previously committed next key, and the newly committed next key MUST be freshly generated inside the authenticator. Even if the platform and the enterprise services are both compromised, an attacker therefore cannot rotate the identity to a key outside the authenticator.
4. **Events never fork.** Events in a slot advance one at a time (sequence number `s` incremented by 1, `p` referencing the previous event); two events with the same sequence number cannot exist.
5. **Signatures are neither lost nor duplicated.** A signature is durably written in the authenticator before it is returned to the platform. If the response is lost, the same signature is retrieved with Recover; the authenticator signs the event only once. Messages are never persisted. After a successful Reset, the PIN record and all private keys of the old reset epoch are unrecoverable.

This document specifies the authenticator state model, the parameters and processing algorithm of each command, data structures and status codes, for use by firmware implementers, wallets, enterprise services and external auditors.

### 1.2 Scope

This document defines the interface between the authenticator and the platform, and the format of enterprise-signed objects consumed by the authenticator. The internal protocols of enterprise gateways, KERIA, witnesses and wallets are out of scope; Section 12 states only their requirements for using authenticator output.

---

## 2. Conformance

The key words "**MUST**", "**MUST NOT**", "**SHOULD**", "**SHOULD NOT**" and "**MAY**" in this document are to be interpreted as described in RFC 2119.

- Numbered algorithms introduced with "The authenticator performs the following steps" are normative: the externally observable behavior of the authenticator (the status code returned, whether state is written, whether output is produced) MUST equal the result of executing those steps in order.
- **Error precedence is unspecified.** When a request violates several conditions, the authenticator MAY return any of the corresponding errors; platforms MUST NOT base decisions on error precedence.
- Status codes are not cryptographic proof. A platform MUST NOT treat `OK` alone as proof that a business operation completed, nor treat an error alone as proof that nothing was committed (§12.3).

---

## 3. Terminology and Notation

### 3.1 Terms

Command names, subcommand names, field names, data structure names, status codes and constants match the wire encoding exactly. Terms already defined by KERI or ISO/IEC 7816 retain their standard meanings. Terms marked "(VCAP)" are specific to this protocol.

| Term | Meaning |
|---|---|
| authenticator | The hardware signing device in this protocol, i.e. the vLEI Key |
| platform | Software that communicates directly with the authenticator, such as a wallet, an IT tool or a manufacturing tool |
| enterprise | The organization that holds the enterprise root key and operates the Ticket issuer and gateway |
| manufacturer | The party that generates the attestation identity and issues its certificate chain at manufacturing time |
| Ticket issuer | The enterprise service that issues Tickets |
| transport | One logical link: one CTAPHID channel over USB, or one NFC field |
| context | Volatile state established by ClientPIN getKeyAgreement and bound to one transport, comprising the key agreement key, contextId, token and upload state |
| pinUvAuthToken (token) | A 32-byte random value issued after successful PIN verification, used to authenticate subsequent commands |
| user presence (UP) | One new press of the touch sensor by the user, or over NFC one tap into the reader's field (§8.2) |
| attestation key / attestation public key | The Ed25519 key pair in the authenticator used to sign StateProof |
| attestation identity | The attestation key together with the certificate chain issued for it by the manufacturer |
| enterprise root key | The enterprise public key bound by BindEnterprise and used to verify TrustConfig (field `enterpriseRoot`) |
| role key | A public key registered in TrustConfig and used to issue Tickets |
| tenant | Digest of the enterprise identifier (§6.3) |
| personalization | Installation of TrustConfig (a general smart-card term); corresponds to the Personalize command |
| lifecycle | The device-level state of the authenticator (§5.1) |
| slot | An independent location holding one KERI identifier and its keys; there are 4, numbered 0..3 (VCAP) |
| owner | The identity category of a slot: CLIENT=1, WORK=2 (VCAP) |
| phase | Slot state: UNUSED=0, CREATED=1, ACTIVE=2 (VCAP) |
| current key / next key | In KERI, the key currently used for signing, and the next key committed by pre-rotation |
| pre-rotation | The KERI mechanism by which the current event commits in advance to the digest of the next key |
| next key commitment | The next key digest in the `n` field of a KERI event |
| prepared key (newNext) | A key generated by PrepareRotation that becomes the new next key at the next rotation (VCAP) |
| latest (head) | The type, sequence number, SAID, length, digest and original signature of the most recent committed key event of a slot |
| KeyRef | A 32-byte reference derived from the device, reset epoch, slot, owner and the actual signing public key (VCAP, §6.3) |
| Ticket | A signing authorization object issued by the Ticket issuer (VCAP, §9.3) |
| TrustConfig | Device configuration signed by the enterprise root key (VCAP, §9.2) |
| StateProof | Authenticator state signed by the attestation key (VCAP, §9.4) |
| reset epoch (`resetEpoch`) | A counter incremented by 1 after each successful Reset |
| atomic commit | A set of persistent writes that take effect entirely or not at all |
| reset intent record | A record durably written by Reset before secrets are destroyed, used to complete the Reset at the next boot after a power loss |
| domain separation tag | A fixed string prepended to a signature or MAC input to distinguish its purpose |
| zeroize | Clear and invalidate volatile secrets and state |
| challenge | A single-use 32-byte random value generated by a verifier to establish the freshness of a StateProof |
| initial usage time limit | The time within which a token MUST be first used to authenticate a command after it is issued |
| power-cycle lockout | After a threshold of consecutive PIN failures, further verification requires a power cycle |
| PIN retry counter | The durably stored number of remaining PIN attempts |
| Outbox | Platform storage in which a message is durably saved before it is signed |
| archive | Durable enterprise storage of messages and their signatures |

### 3.2 Notation

| Symbol | Meaning |
|---|---|
| `H(x)` | SHA-256 |
| `‖` | Byte concatenation |
| `\0` | One zero byte |
| `bN` | A CBOR bstr of exactly N bytes, e.g. `signature_b64` is a 64-byte bstr (not Base64) |
| `tN` | A CBOR tstr of exactly N bytes, e.g. `aid_t44` |
| `_BE8` | An 8-byte big-endian unsigned integer |
| `[a,b,…]` | CBOR array |
| `{k:v,…}` | CBOR map with unsigned integer keys |
| `X_bstr` | The deterministic CBOR encoding of X embedded as a bstr |

---

## 4. Protocol Overview

### 4.1 Participants and Trust Relationships

```
Manufacturer ── generates attestation identity, issues certificate chain ──▶ Authenticator
Enterprise root key ── bound by BindEnterprise; signs TrustConfig (registers role keys) ──▶ Authenticator
Role key ── issues Ticket ──▶ Platform ──▶ Authenticator

Authenticator (attestation key, 4 slots) ◀─CTAPHID / NFC─▶ Platform (wallet) ◀─HTTPS─▶ Ticket issuer / gateway ──▶ KERIA / witnesses / recipients
```

- The authenticator trusts only: its own attestation identity, the enterprise root key bound by BindEnterprise, the TrustConfig role keys installed under a signature of the enterprise root key, and the employee's PIN and touch.
- The platform is untrusted: it can block, reorder and observe the link, and can send any command with a valid token. A new signature still requires an enterprise Ticket and a new UP, and every rotation stays within keys inside the authenticator.
- The enterprise cannot sign alone: role keys only issue Tickets, and a signature requires the employee's PIN authorization and a physical user action.

### 4.2 Lifecycle Overview

```
Manufacturing: STOCK initialization ──> STOCK_UNBOUND
   │ BindEnterprise (tenant + enterprise root public key + UP, controlled environment)
   ▼
ENTERPRISE_BOUND
   │ Personalize (TrustConfig signed by the enterprise root key + UP)
   ▼
PERSONALIZED_NO_PIN
   │ ClientPIN setPIN (by the employee)
   ▼
PIN_READY ── CreateIdentity / Sign(icp,ixn,rot,exn,rpy,agent) / PrepareRotation / Recover / GetState …
   │ Reset (within 10 s of power-up + 5 s hold)
   ▼
ENTERPRISE_BOUND (binding unchanged, resetEpoch+1, not personalized) ──> Personalize again
```

At any stage, if the authenticator finds unrecognized or corrupted data in storage at boot, it enters `RECOVERY_REQUIRED` (§5.1); an incomplete Reset is completed at boot (§7.12.4).

### 4.3 A Normal Signature

```
Platform                             Authenticator                        Enterprise
  |-- open transport --------------->|                                    |
  |-- getKeyAgreement -------------->|  new P-256 key and contextId
  |<-- keyAgreement -----------------|                                    |
  |-- message + contextId + context age --------------------------------->|  store message, approve
  |-- getPinUvAuthToken...(READ|SIGN)>  decrement, compare PIN, reset to 8 on success
  |<-- pinUvAuthToken ---------------|                                    |
  |<-- Ticket ------------------------------------------------------------|
  |   write message to Outbox        |                                    |
  |-- Sign / Upload* --------------->|  verify Ticket, parse, wait for UP
  |                                  |  (user touches once), sign, self-verify, commit
  |<-- Signed -----------------------|                                    |
  |   verify signature, archive ---------------------------------------->|
```

The enterprise approves based on its archived head, the Ticket request runs in parallel with PIN entry, and a normal signature takes one business exchange with the authenticator (Sign). When the enterprise has no usable head or an earlier outcome is unknown, the platform first calls GetState with an enterprise-generated challenge and submits the resulting StateProof with the message (§12.2).

---

## 5. Authenticator State Model

Authenticator state consists of **persistent state** (lifecycle, four slots, PIN record, reset intent record) and **volatile state** (context, token, upload, power-cycle lockout count, power-up time).

### 5.1 Device Lifecycle

The `lifecycle` field of status-mode GetState (§7.4.1) reports the following values:

| Value | Name | Meaning |
|---:|---|---|
| 0 | STOCK_UNBOUND | Factory state: attestation identity only, not bound to an enterprise |
| 1 | ENTERPRISE_BOUND | Bound to a tenant and enterprise root key; not personalized in this reset epoch |
| 2 | PERSONALIZED_NO_PIN | TrustConfig and four UNUSED slots installed; no PIN set |
| 3 | PIN_READY | PIN set (says nothing about lockout; retry state is reported by ClientPIN) |
| 4 | RECOVERY_REQUIRED | Storage contains unrecognized or corrupted data |

Transitions:

| Current | Event | Next | Condition |
|---|---|---|---|
| — | Manufacturer STOCK initialization | STOCK_UNBOUND | Created only by an explicit manufacturing procedure; a normal boot MUST NOT treat unrecognized storage as an empty device and format it |
| STOCK_UNBOUND | BindEnterprise succeeds | ENTERPRISE_BOUND | §7.10 |
| ENTERPRISE_BOUND | Personalize succeeds | PERSONALIZED_NO_PIN | §7.11 |
| PERSONALIZED_NO_PIN | setPIN succeeds | PIN_READY | §7.2.4 |
| PERSONALIZED_NO_PIN / PIN_READY | Reset succeeds | ENTERPRISE_BOUND (resetEpoch+1) | §7.12; tenant and enterprise root key retained |
| Any | Unrecognized or corrupted data found at boot | RECOVERY_REQUIRED | The affected data is retained |
| Any | Valid reset intent record found at boot | ENTERPRISE_BOUND (resetEpoch+1) | Reset completed at boot (§7.12.4) |

Constraints:

- The binding is permanent: a bound authenticator cannot be rebound or returned to the factory state.
- Missing data **MUST NOT** be treated as UNUSED or not personalized; if `personalized=1` and the configuration or a slot record is missing, it SHOULD be treated as corruption.
- In `RECOVERY_REQUIRED`, every command except `GetInfo`, status-mode `GetState` and `Cancel` (including ClientPIN) returns `RECOVERY_REQUIRED`.

### 5.2 Slot State

```
         CreateIdentity                  Sign(ICP) committed
UNUSED ────────────────▶ CREATED ─────────────────────▶ ACTIVE ──┐
 (phase 0)                (phase 1)                     (phase 2)│ Sign(IXN) committed: head advances
                                                          ▲  │   │ Sign(ROT) committed: current←old.next,
                                                          │  │   │   next←newNext, prepared deleted
                                                          └──┘◀──┘
                              PrepareRotation (WORK only): sets prepared, head unchanged
                              Reset: all four slots return to UNUSED (new reset epoch)
```

| phase | owner | current / next | prepared | aid / head |
|---|---|---|---|---|
| UNUSED | 0 | null | null | null |
| CREATED | 1 or 2 | present | null | null |
| ACTIVE | 1 or 2 | present | WORK only, optional | present |

- Any mix of owners is permitted, including four WORK slots. Slots are independent of one another and hold no receipts or pending events. A slot keeps its identity until Reset, which returns all slots to UNUSED together.
- A CLIENT slot permits ICP / IXN / AGENT; a WORK slot permits ICP / IXN / ROT / EXN / RPY.
- When `prepared` exists, a further PrepareRotation returns the existing preparation unchanged.

### 5.3 Context and Token

```
           getKeyAgreement (same transport, no upload)
  NONE ──────────────────────────────────────▶ CONTEXT (no token)
   ▲                                              │ getPinUvAuthToken... succeeds
   │                                              ▼
   │  zeroization event (below)                CONTEXT (token with permissions)
   └──────────────────────────────────────────────┤ getPinUvAuthToken... again: token replaced (permissions not accumulated)
                                                  │ unused 19.8 s after issue: token invalid
```

- One transport has one context; a context lives at most 600 000 ms from its establishment.
- A context is **held** while its token carries a VCAP permission bit (READ, SIGN or MANAGE, §7.0), while a command is executing in it, or while an upload is in progress. A context created by a client that requests only CTAP permissions (for example a browser performing WebAuthn) is never held.
- While a held context exists, any command other than `GetInfo` and status-mode `GetState` from another transport receives `BUSY`; the held context is kept.
- A context that is not held is zeroized when another transport sends a command that requires a context or a ClientPIN subcommand other than getPinRetries; that command then proceeds normally.
- A new `getKeyAgreement` on the same transport first zeroizes the old context and then establishes a new one; during an upload it returns `BUSY` per §5.4.
- A token MUST be first used to authenticate a command within 19 800 ms of issue (the initial usage time limit; CTAP uses this value for NFC, and VCAP applies it to all transports), or it becomes invalid. After first use it remains valid until the context ends (maximum usage period 600 000 ms), with no idle timeout.
- **Zeroization events:** transport disconnection, NFC `SELECT`, `CTAPHID_CANCEL`, the `Cancel` command, context expiry, token expiry detected, authentication or integrity failure, successful BindEnterprise / Personalize / Reset, and the errors listed in §10.2. Zeroization clears the fragment buffer, pending response, upload and signer, parser, token, X25519 key agreement key and contextId. The persistent KEL head and prepared key are kept.

### 5.4 Upload State

```
IDLE ──UploadBegin ok──▶ RECEIVING(offset=0) ──UploadChunk(correct offset)──▶ RECEIVING(offset+n)
  ▲                              │                                             │ offset == declared length
  │                              │ any error / Cancel / disconnect / expiry      ▼
  └──────────────────────────────┴────────────────────── UploadEnd ─────── COMPLETE → output Signed
```

- During an upload only `UploadChunk`, `UploadEnd`, `Cancel`, `GetInfo` and status-mode `GetState` are accepted. Any other command (including another `UploadBegin`) returns `BUSY` and **MUST NOT** zeroize the current upload.
- `GetInfo` and status-mode `GetState` leave context and upload deadlines unchanged.
- Any error other than `BUSY` during an upload zeroizes the upload and the whole context; when UploadEnd returns `USER_ACTION_TIMEOUT`, only the upload is cleared and the context and token are kept (§10.2).

### 5.5 Reset State

```
NORMAL ──Reset (within 10 s of power-up) + 5 s hold──▶ reset intent record written ──secrets made unrecoverable──▶
       employee data deleted, resetEpoch+1 published ──▶ ENTERPRISE_BOUND

power loss after the reset intent record is written ──▶ Reset completed at next boot ──▶ ENTERPRISE_BOUND
```

Once the reset intent record is written, the Reset runs to completion: it MUST NOT be withdrawn, and secrets MUST be made unrecoverable rather than logically deleted.

---

## 6. Encoding, Identifiers and Cryptographic Primitives

### 6.1 Deterministic CBOR

All CBOR sent and received by the authenticator MUST satisfy:

1. Integers and lengths use the shortest definite-length encoding; indefinite-length encoding MUST NOT be used.
2. A tstr MUST be valid UTF-8.
3. Tags, floating-point numbers, simple values (`null` only where explicitly permitted by this document) and trailing bytes MUST NOT appear.
4. Nesting depth ≤ 16 and total item count ≤ 1024.
5. Keys of ordinary maps MUST be unsigned integers in strictly increasing order.
6. Sole exception: COSE_Key uses negative integer keys per RFC 9053, `{1:2,3:-25,-1:1,-2:x_b32,-3:y_b32}`, in key order 1, 3, -1, -2, -3 (deterministic CBOR ordering).
7. Unknown, missing and extra keys are all rejected.

Violations of items 1–4 and 6 return `INVALID_CBOR`; key-set violations of items 5 and 7 return `INVALID_PARAMETER` (a ClientPIN request missing a required parameter returns `MISSING_PARAMETER`, §7.2); out-of-range lengths or integers return `INVALID_LENGTH`.

### 6.2 Byte Conventions

- All fixed-width integers are big-endian unsigned.
- Signatures are 64-byte `R‖S`; public keys are 32-byte compressed Ed25519 points.
- AID, SAID and prior are 44-byte KERI qb64 text beginning with `E`.

### 6.3 Identifier Derivation

```
device     = H("VHKP-DEVICE-ID\0" ‖ attestationPublic_raw32)
tenant     = H(UTF-8 encoding of the enterprise identifier)
configurationDigest = H(complete TrustConfig envelope)
KeyRef     = H("VHKP-KEYREF\0" ‖ device ‖ resetEpoch_BE8 ‖ CBOR([slot, owner]) ‖ actualPublic_raw32)
contextId  = H("VHKP-CONTEXT\0" ‖ keyAgreement.x)   ; the authenticator's keyAgreement
```

`actualPublic` is **the public key actually used for this signature**: current for ICP / IXN / EXN / RPY / AGENT, and old.next for ROT. The authenticator computes KeyRef from its own verified slot state and MUST NOT use a KeyRef or digest supplied by the platform.

### 6.4 Cryptographic Primitives

| Purpose | Algorithm | Notes |
|---|---|---|
| Business signatures, attestation signatures | Strict pure Ed25519 (hedged) | Rejects non-canonical encodings and unsafe public keys (small-order points or points outside the prime-order subgroup) |
| Digest | SHA-256 | |
| KERI next key commitment / E encoding | BLAKE3-256 | As defined by KERI |
| PIN key agreement | ECDH on P-256 (CTAP pinUvAuthProtocol 2) | A peer point not on the curve is rejected |
| PIN KDF / MAC | HKDF-SHA-256 / HMAC-SHA-256 (CTAP pinUvAuthProtocol 2) | §7.2.1 |
| PIN encryption | AES-256-CBC, random IV, no padding | |

Each purpose has one fixed algorithm; algorithms are not negotiated.

**Hedged pure Ed25519:** the signature nonce `r` is derived jointly from RNG output and the digest of the object being signed (§8.6). The output is a standard Ed25519 signature verifiable by any standard verifier.

### 6.5 Signature Domains

Each signed object uses a unique domain separation tag. Verifiers MUST use the prefixes below byte for byte.

| Domain separation tag | Signer | Signed content | Definition |
|---|---|---|---|
| `"VHKP-STATE\0"` | Attestation key | `stateBody` bytes | §9.4 |
| `"VHKP-TRUST\0"` | Enterprise root key | TrustConfig `body` bytes | §9.2 |
| `"VHKP-SIGN\0"` | TrustConfig role key | Ticket `body` bytes | §9.3 |
| `"VHKP-CMD\0"` | HMAC(token) | Command authentication message | §8.1 |
| `"VHKP-AGENT-SESSION\0"` | Slot current key (kind 6) | AGENT message prefix | §8.5.3 |
| (no prefix) | Slot key | KERI message | §8.4, §8.5 |

---

## 7. Authenticator API

### 7.0 Command Table

Command codes `0x00`–`0x3F` are the CTAP command codes and are used only for commands whose function is the same as the CTAP command. VCAP-specific commands use the CTAP vendor command range `0x40`–`0xBF`. The authenticator also implements the standard CTAP authenticator operations (§7.13), so it serves as a FIDO2 security key for WebAuthn.

| Code | Command | Business parameters (excluding pinUvAuthProtocol / pinUvAuthParam) | Token permission | UP | Result | Context closed on success |
|---|---|---|---|---|---|---|
| 0x01 | authenticatorMakeCredential | As CTAP (§7.13) | CTAP `mc` | **Yes** | As CTAP | No |
| 0x02 | authenticatorGetAssertion | As CTAP (§7.13) | CTAP `ga` | **Yes** | As CTAP | No |
| 0x04 | GetInfo | none | None (public) | No | authenticatorGetInfo map (§7.1) | No |
| 0x06 | ClientPIN | See §7.2 | None (self-authenticating) | No | See §7.2 | No |
| 0x07 | Reset | none | None; within 10 s of power-up | **Yes (5 s hold)** | Empty | Yes |
| 0x08 | authenticatorGetNextAssertion | As CTAP (§7.13) | — | No | As CTAP | No |
| 0x0B | authenticatorSelection | As CTAP (§7.13) | None | **Yes** | As CTAP | No |
| 0x40 | GetState | Status mode: `{}`; proof mode: `{1:challenge_b32}` | Status mode: none (public); proof mode: READ | No | Status mode: `{1:lifecycle}`; proof mode: StateProof | No |
| 0x41 | CreateIdentity | `{1:slot,2:owner,3:challenge_b32}` | READ+MANAGE | No | StateProof | No |
| 0x43 | Sign | `{1:slot,2:kind,3:ticket_bstr,4:original_bstr}` | SIGN | **Yes** | Signed | No |
| 0x44 | PrepareRotation | `{1:slot,2:challenge_b32}` | READ+SIGN | No | StateProof | No |
| 0x46 | Recover | `{1:slot,2:originalDigest_b32}` | READ | No | Signed (original signature) | No |
| 0x47 | Cancel | `{}` | None (owning transport only) | No | Empty | Yes |
| 0x60 | Personalize | `{1:trustConfigEnvelope_bstr}` | None; requires context + enterprise root signature | **Yes** | Empty | Yes |
| 0x63 | BindEnterprise | `{1:tenant_b32,2:enterpriseRoot_b32}` | None; requires context | **Yes** | Empty | Yes |
| 0x70 | UploadBegin | `{1:slot,2:kind,3:ticket_bstr}` | SIGN | No | Empty | No |
| 0x71 | UploadChunk | `{1:offset,2:bytes_bstr}` | SIGN | No | Empty | No |
| 0x72 | UploadEnd | `{}` | SIGN | **Yes** | Signed | No |

GetInfo and Reset carry no parameter map, as in CTAP.

Commands that require a token permission append two keys after the business parameters: `254` = **pinUvAuthProtocol** (fixed at 2) and `255` = **pinUvAuthParam** (32 bytes, §8.1). Parameters below are written as `254:2, 255:pinUvAuthParam_b32`.

VCAP permission bits: `READ=0x0100`, `SIGN=0x0200`, `MANAGE=0x0400`. They lie above the CTAP permission bits (`0x01`–`0x80`), so a single permissions value can carry both. VCAP commands check only the VCAP bits.

### 7.0.1 Command Dispatch

For each completely reassembled request, the authenticator performs the following steps:

1. If a context exists on a transport other than the one carrying this request, and the command is not `GetInfo` or status-mode `GetState` (GetState with an empty parameter map, §7.4): if that context is held (§5.3), return `BUSY` without changing any state; otherwise zeroize it per §8.8 and continue.
2. If an upload is in progress and the command is not `GetInfo` / status-mode `GetState` / `Cancel` / `UploadChunk` / `UploadEnd`, return `BUSY`; the upload MUST NOT be zeroized.
3. If a context exists, check the context and token deadlines (§8.1 step 4); on expiry return `PIN_TOKEN_EXPIRED` and zeroize the context.
4. Decode `command_u8`; an unknown command returns `INVALID_COMMAND`. Decode the parameters per §6.1.
5. If the command is `GetInfo`, execute §7.1. If the command is status-mode `GetState`, execute §7.4.1. If the command is `Cancel`, execute §7.3.
6. If the authenticator is in `RECOVERY_REQUIRED`, return `RECOVERY_REQUIRED`.
7. If the command is `ClientPIN`, execute §7.2. If the command is a standard CTAP operation (§7.13), execute it as §7.13 specifies.
8. If the command requires a token permission, determine the required permission from the command table in §7.0 and execute §8.1. Otherwise (except Reset) a context is required; if absent, return `PUAT_REQUIRED`.
9. Execute the command.
10. After the command succeeds, confirm again that the deadlines and permissions are still valid (§8.1 steps 4 and 7); otherwise return the corresponding error.
11. If the transport was replaced during execution, zeroize the context and return `OPERATION_DENIED`.
12. If an error is returned, decide per §10.2 whether to zeroize the context.

### 7.1 GetInfo (0x04)

Same function and encoding as CTAP authenticatorGetInfo. The request is the command byte alone.

**Result:** the authenticatorGetInfo response map. VCAP uses the following members:

| Key | Name | VCAP value |
|---:|---|---|
| 0x01 | versions | `["FIDO_2_0", "FIDO_2_1"]` |
| 0x02 | extensions | The CTAP extensions supported for standard operations (§7.13) |
| 0x03 | aaguid | The AAGUID of the authenticator model |
| 0x04 | options | `rk`: true; `up`: true; `clientPin`: true once a PIN is set (lifecycle PIN_READY), otherwise false; `pinUvAuthToken`: true |
| 0x05 | maxMsgSize | 2048 |
| 0x06 | pinUvAuthProtocols | `[2]` (§7.2) |
| 0x0A | algorithms | ES256 (-7) and EdDSA (-8) for standard operations |
| 0x0D | minPINLength | TrustConfig `minPinChars`; 4 before personalization |
| 0x0E | firmwareVersion | Firmware version (uint) |

The authenticator performs the following steps:

1. If the request carries any byte after the command byte, return `INVALID_LENGTH`.
2. Return the result. Any state, including context and upload deadlines, MUST remain unchanged.

The result is unsigned and serves discovery and display.

The VCAP lifecycle is reported by status-mode GetState (§7.4.1).

### 7.2 ClientPIN (0x06)

This command provides PIN setting, PIN change and token acquisition using **pinUvAuthProtocol 2** of CTAP (§7.2.1). Parameter keys: `1=pinUvAuthProtocol`, `2=subCommand`, `3=keyAgreement`, `4=pinUvAuthParam`, `5=newPinEnc`, `6=pinHashEnc`, `9=permissions`. Response keys: `1=keyAgreement`, `2=pinUvAuthToken`, `3=pinRetries`, `4=powerCycleState`. A missing parameter required by the subcommand returns `MISSING_PARAMETER`. The command code, subcommand codes, parameter keys and response keys are those of CTAP authenticatorClientPIN, and the PIN/UV auth protocol is CTAP pinUvAuthProtocol 2. Only the subcommands below are used by VCAP.

| subCommand | Name | Complete request parameters | Response |
|---:|---|---|---|
| 0x01 | getPinRetries | `{1:2,2:1}` | `{3:pinRetries,4:powerCycleState}` |
| 0x02 | getKeyAgreement | `{1:2,2:2}` | `{1:keyAgreement}` |
| 0x03 | setPIN | `{1:2,2:3,3:keyAgreement,4:pinUvAuthParam_b32,5:newPinEnc_b80}` | Empty |
| 0x04 | changePIN | `{1:2,2:4,3:keyAgreement,4:pinUvAuthParam_b32,5:newPinEnc_b80,6:pinHashEnc_b32}` | Empty |
| 0x09 | getPinUvAuthTokenUsingPinWithPermissions | `{1:2,2:9,3:keyAgreement,6:pinHashEnc_b32,9:permissions}` | `{2:pinUvAuthToken_b48}` |

`pinUvAuthProtocol≠2` returns `INVALID_PARAMETER`; an unknown subCommand returns `INVALID_COMMAND`.

#### 7.2.1 pinUvAuthProtocol 2 Primitives

VCAP uses CTAP pinUvAuthProtocol 2 unchanged: P-256 ECDH key agreement, HKDF-SHA-256 key derivation, AES-256-CBC encryption and HMAC-SHA-256 authentication.

```
ecdh(peerCOSE):
    if peer is not a valid point on P-256, return INVALID_PARAMETER
    Z    = x-coordinate of (own private key · peer point), 32 bytes
    Kmac = HKDF-SHA-256(salt = zero32, IKM = Z, L = 32, info = "CTAP2 HMAC key")
    Kaes = HKDF-SHA-256(salt = zero32, IKM = Z, L = 32, info = "CTAP2 AES key")

encrypt(M)      = IV_b16 ‖ AES-256-CBC(Kaes, IV, M)      ; M is whole blocks, no PKCS#7; fresh random IV each time
decrypt(C)      = AES-256-CBC⁻¹(Kaes, C[0..16], C[16..])  ; length < 16 or not a multiple of 16: INVALID_PARAMETER
authenticate(M) = HMAC-SHA-256(Kmac, M)                   ; full 32 bytes
verify(M, sig)  = if sig is not 32 bytes, INVALID_PARAMETER; otherwise compare authenticate(M) with sig in constant time, mismatch: PIN_AUTH_INVALID
```

COSE_Key MUST be exactly `{1:2,3:-25,-1:1,-2:x_b32,-3:y_b32}` (kty=EC2, alg=ECDH-ES+HKDF-256, crv=P-256), as in CTAP.

PIN rules:

- `paddedNewPin` MUST be exactly 64 bytes, otherwise `INVALID_PARAMETER`. Stripping trailing 0x00 bytes yields newPin; newPin MUST be ≤ 63 bytes and contain at least TrustConfig `minPinChars` (4..63) Unicode code points counted over its UTF-8 encoding, otherwise `PIN_POLICY_VIOLATION`. The authenticator applies no normalization.
- Wire format: right-pad with zeros to 64 bytes, then encrypt; `newPinEnc` = 16-byte IV + 64-byte ciphertext = 80 bytes.
- `pinHash = LEFT(SHA-256(UTF-8 bytes of the PIN), 16)` (without padding); `pinHashEnc` = 16-byte IV + 16-byte ciphertext = 32 bytes.
- `pinUvAuthToken` (encrypted) = 16-byte IV + 32-byte ciphertext = 48 bytes.

#### 7.2.2 getPinRetries (0x01)

No context is required. A held context on another transport still returns `BUSY` (§7.0.1 step 1); a context that is not held is left in place.

The authenticator performs the following steps:

1. Return `{3:pinRetries, 4:powerCycleState}`: `pinRetries` is the persistent PIN retry counter (0..8; 8 when no PIN is set); `powerCycleState` is true when the consecutive failure count has reached 3 and a power cycle is required.
2. Any state MUST remain unchanged.

#### 7.2.3 getKeyAgreement (0x02)

Establishes a new context and returns its P-256 key agreement public key.

**Result:** `{1:keyAgreement}`, the authenticator's newly generated P-256 public key (§9.1).

The authenticator performs the following steps:

1. Validate the parameter key set.
2. Zeroize the existing context of this transport, if any.
3. Generate a new P-256 key pair (the private key of an earlier context MUST NOT be reused); compute `contextId` per §6.3. The context clock starts at 0.
4. Register the context to this transport and return the result.

The platform computes contextId from keyAgreement per §6.3. This command grants no PIN or business permission and does not authenticate the authenticator.

#### 7.2.4 setPIN (0x03)

The authenticator performs the following steps:

1. If keyAgreement, pinUvAuthParam or newPinEnc is missing, return `MISSING_PARAMETER`.
2. If no context exists, return `PUAT_REQUIRED`.
3. If a PIN is already set, return `PIN_AUTH_INVALID`.
4. `sharedSecret = ecdh(keyAgreement)`; on failure return `INVALID_PARAMETER`.
5. If `verify(sharedSecret, newPinEnc, pinUvAuthParam)` fails, return `PIN_AUTH_INVALID`.
6. `paddedNewPin = decrypt(sharedSecret, newPinEnc)`; on failure return `PIN_AUTH_INVALID`.
7. If not personalized (no TrustConfig and therefore no minPinChars), return `PIN_POLICY_VIOLATION`; otherwise derive and check newPin per the PIN rules of §7.2.1.
8. Durably write `LEFT(SHA-256(newPin), 16)` and set pinRetries to 8.
9. Return empty success.

#### 7.2.5 changePIN (0x04)

The authenticator performs the following steps:

1. If keyAgreement, pinUvAuthParam, newPinEnc or pinHashEnc is missing, return `MISSING_PARAMETER`.
2. If no context exists, return `PUAT_REQUIRED`; if no PIN is set, return `PIN_NOT_SET`.
3. If pinRetries is 0, return `PIN_BLOCKED`.
4. `sharedSecret = ecdh(keyAgreement)`; on failure return `INVALID_PARAMETER`.
5. If `verify(sharedSecret, newPinEnc ‖ pinHashEnc, pinUvAuthParam)` fails, return `PIN_AUTH_INVALID`.
6. Execute the PIN verification procedure of §7.2.7; on failure return as specified there.
7. `paddedNewPin = decrypt(sharedSecret, newPinEnc)`; on failure return `PIN_AUTH_INVALID`. Derive and check newPin per the PIN rules of §7.2.1.
8. Durably write `LEFT(SHA-256(newPin), 16)`.
9. Revoke the current token.
10. Return empty success.

#### 7.2.6 getPinUvAuthTokenUsingPinWithPermissions (0x09)

**Result:** `{2:pinUvAuthToken_b48}`.

The authenticator performs the following steps:

1. If keyAgreement, pinHashEnc or permissions is missing, return `MISSING_PARAMETER`.
2. Discard bits other than READ|SIGN|MANAGE (and any CTAP permission bits the authenticator supports for CTAP commands); if the result is 0, return `INVALID_PARAMETER`.
3. If no context exists, return `PUAT_REQUIRED`; if no PIN is set, return `PIN_NOT_SET`.
4. If pinRetries is 0, return `PIN_BLOCKED`.
5. `sharedSecret = ecdh(keyAgreement)`; on failure return `INVALID_PARAMETER`.
6. Execute the PIN verification procedure of §7.2.7; on failure return as specified there.
7. Generate a new random 32-byte token that **replaces** the old token (the old token is invalid immediately). Its permissions are the defined bits of this request's permissions (not a union with earlier permissions). The token carries no user presence state. The initial usage time limit starts now (§5.3).
8. Return `{2: encrypt(sharedSecret, token)}`.

The token exists only in volatile memory; the PIN is never cached.

#### 7.2.7 PIN Verification Procedure and Lockout

**PIN verification procedure** (inputs: sharedSecret, pinHashEnc):

1. If the consecutive failure count has reached 3, return `PIN_AUTH_BLOCKED`.
2. Durably write `pinRetries ← pinRetries − 1` (decrement first).
3. Decrypt pinHashEnc and compare it in constant time with the stored 16-byte value.
4. On mismatch:
   1. Zeroize the context (the key agreement key changes with it); the platform MUST call getKeyAgreement again.
   2. If pinRetries is 0, return `PIN_BLOCKED`.
   3. Increment the consecutive failure count; if it reaches 3, return `PIN_AUTH_BLOCKED`.
   4. Return `PIN_INVALID`.
5. On match: durably write `pinRetries ← 8` and reset the consecutive failure count to 0.

Rules:

| Rule | Value |
|---|---|
| PIN retry counter | 8; when exhausted the PIN is permanently blocked and only Reset recovers |
| Power-cycle lockout after consecutive failures | 3; volatile only, cleared by a power cycle; the persistent balance is not restored |
| Power loss / error response / reconnection | Decremented attempts are not refunded |
| Syntax or structure error | PIN not verified, no decrement |

### 7.3 Cancel (0x47)

**Parameters:** `{}`. **Result:** empty.

The authenticator performs the following steps:

1. If the parameters are not an empty map, return `INVALID_PARAMETER`.
2. If a held context exists on another transport, return `BUSY` (§7.0.1 step 1).
3. Zeroize the context of this transport per §8.8; the persistent KEL head and prepared key are kept.
4. Return `OK`.

Cancel requires neither a token nor UP. A successful Cancel **does not prove** that an earlier command was not committed.

> Note: while waiting for UP, the authenticator is inside the current command (§8.2), so a Cancel command cannot arrive on the same transport during that time. Cancellation during the wait uses the transport: `CTAPHID_CANCEL` over USB (§11.2), removal from the field over NFC (§11.3), or a UP timeout.

### 7.4 GetState (0x40)

GetState has two modes, selected by its parameters:

- **Status mode:** empty parameter map. Reports the lifecycle without authentication, in every lifecycle state.
- **Proof mode:** a challenge and token authentication. Returns the complete state of the four slots, signed with the attestation key.

A request with a challenge but without pinUvAuthParam returns `PUAT_REQUIRED`. Neither mode requires UP or writes persistent state.

#### 7.4.1 Status Mode

**Parameters:** `{}`. **Required permission:** none; no context required. **Result:**

| Key | Name | Type | Description |
|---:|---|---|---|
| 1 | lifecycle | uint | §5.1; 4 in `RECOVERY_REQUIRED` |

The authenticator performs the following steps:

1. Return the result. Any state, including context and upload deadlines, MUST remain unchanged.

The result is unsigned, carries no device identifier, and serves discovery and display.

#### 7.4.2 Proof Mode

**Parameters:** `{1:challenge_b32, 254:2, 255:pinUvAuthParam_b32}`. **Required permission:** READ. **Result:** StateProof (§9.4).

The authenticator performs the following steps:

1. Authenticate per §8.1 (READ).
2. If not personalized, return `INVALID_STATE`.
3. Read the persistent state of the four slots; if the state of any slot is missing, corrupted, or not of the current reset epoch and configuration, return `RECOVERY_REQUIRED`.
4. Construct `authState` from the PIN record's `pinRetries`, the power-cycle lockout state, the current token permissions, the remaining initial-usage milliseconds (0 if already used) and the remaining context milliseconds.
5. Construct `stateBody` (§9.4); `contextAgeMs` is the elapsed context time at signing.
6. Compute `signature = Ed25519(attestation key, "VHKP-STATE\0" ‖ stateBody)`.
7. Return `{1:stateBody_bstr, 2:signature}`.

A StateProof carries no lifecycle field: proof mode requires a PIN token, so the lifecycle is always PIN_READY. When the enterprise uses a StateProof as the basis for issuing a Ticket, the challenge MUST be generated by the enterprise and used only once.

### 7.5 CreateIdentity (0x41)

Generates the current and next keys inside the authenticator in an UNUSED slot.

**Parameters:** `{1:slot, 2:owner, 3:challenge_b32, 254:2, 255:pinUvAuthParam_b32}`. **Required permission:** READ+MANAGE. **UP:** no. **Result:** StateProof (including the new state).

The authenticator performs the following steps:

1. Authenticate per §8.1 (READ|MANAGE).
2. If `slot ∉ 0..3` or `owner ∉ {1,2}`, return `INVALID_PARAMETER`.
3. If not personalized, return `INVALID_STATE`.
4. If TrustConfig `ownerMask` does not include the owner, return `OPERATION_DENIED`.
5. If the slot is not UNUSED, return `INVALID_STATE`.
6. Pre-check persistent storage space; if insufficient, return `NO_SPACE`.
7. Generate two Ed25519 seeds, current and next, distinct from each other and from all existing keys in other slots.
8. Atomically commit the slot: current / next seeds, phase=CREATED, owner, currentPublic, nextPublic.
9. After the write completes, generate a StateProof containing this request's challenge per §7.4.2 steps 3–7 and return it.

If the response is lost, the platform MUST NOT resend; it MUST query the actual state with a new GetState. Each slot receives exactly one key set per reset epoch.

### 7.6 PrepareRotation (0x44)

Generates newNext for the next rot.

**Parameters:** `{1:slot, 2:challenge_b32, 254:2, 255:pinUvAuthParam_b32}`. **Required permission:** READ+SIGN. **UP:** no. **Result:** StateProof.

The authenticator performs the following steps:

1. Authenticate per §8.1 (READ|SIGN).
2. If slot is out of range, return `INVALID_PARAMETER`.
3. If the slot is not an ACTIVE WORK slot, return `INVALID_STATE`.
4. If prepared already exists, generate and return a StateProof without writing (same preparation, kept unchanged).
5. Pre-check space; if insufficient, return `NO_SPACE`.
6. Generate a newNext seed distinct from the slot's current and next keys and from all other existing keys.
7. Atomically commit the slot's prepared entry: newNext seed and newNextPublic; latest is unchanged.
8. After the commit, generate and return a StateProof.

### 7.7 Sign (0x43)

Generates a new signature over a message with a slot key. Larger messages use the upload form of §7.9; both forms have the same semantics.

**Parameters:**

| Key | Name | Type | Description |
|---:|---|---|---|
| 1 | slot | uint | 0..3 |
| 2 | kind | uint | 1..6, see below |
| 3 | ticket | bstr | Ticket envelope, ≤ 512 bytes (§9.3) |
| 4 | original | bstr | Message; complete request ≤ 2048 bytes |
| 254 | pinUvAuthProtocol | uint | 3 |
| 255 | pinUvAuthParam | b32 | §8.1 |

**kind:**

| kind | Name | Message type | Allowed owner | Message limit | KEL | Persistent write |
|---:|---|---|---|---:|---|---|
| 1 | ICP | KERI `icp` | CLIENT / WORK | 16384 | Yes | Slot latest |
| 2 | IXN | KERI `ixn` | CLIENT / WORK | 16384 | Yes | Slot latest |
| 3 | ROT | KERI `rot` | WORK | 16384 | Yes | Slot keys, latest; prepared deleted |
| 4 | EXN | KERI `exn` | WORK | 16384 | No | None |
| 5 | RPY | KERI `rpy` | WORK | 16384 | No | None |
| 6 | AGENT | Agent session claims | CLIENT | 512 | No | None |

**Required permission:** SIGN. **UP:** yes, one new user action each time (sensor press, or NFC tap per §8.2). **Result:** Signed (§9.5).

The authenticator performs the following steps (**BEGIN phase**):

1. Authenticate per §8.1 (SIGN).
2. If `slot ∉ 0..3` or `kind ∉ 1..6`, return `INVALID_PARAMETER`.
3. If not personalized, return `INVALID_STATE`.
4. Read the slot's persistent state and verify its integrity (including keys and, where needed, prepared); on failure return `RECOVERY_REQUIRED`.
5. Verify the Ticket per §8.3, obtaining `ticketDigest`, `originalLength` and `originalDigest`.
6. If `kind` is a KEL kind (1..3): perform the key event pre-checks of §8.4.1 and pre-check persistent storage space per §8.7 (insufficient: `NO_SPACE`). Otherwise: require the slot to be ACTIVE (else `INVALID_STATE`) and select the corresponding format check of §8.5.
7. Select the signing seed: old.next for ROT, current otherwise.
8. Generate `R` per §8.6 before receiving the first message byte, and initialize the streaming signer.
9. Confirm again that the transport is still connected and no deadline has passed.

(**Data phase**)

10. Inline form: if `len(original) ≠ originalLength`, return `INVALID_LENGTH`. Upload form: received chunk by chunk per §7.9.2.
11. Feed original byte by byte into the parser, `H(original)` and `H(R‖A‖original)`.

(**END phase**)

12. Confirm that the number of bytes received equals `originalLength`, otherwise `UPLOAD_INVALID`.
13. If `H(original) ≠ originalDigest`, return `TICKET_INVALID`.
14. Confirm that the context and token are still valid and the transport is unchanged.
15. Confirm again that the Ticket has not expired (§8.3 step 11), otherwise return `TICKET_INVALID`.
16. KEL: complete the event checks of §8.4.2 (message fully parsed, fields and key bindings consistent); on failure return `INVALID_KERI_EVENT` or `KEY_BINDING`. Non-KEL: complete the format check of §8.5; on failure return `INVALID_KERI_EVENT`.
17. Collect one UP per §8.2 (hold 0).
18. After UP, check again: transport still connected (else `OPERATION_DENIED`), persistent storage space for KEL (else `NO_SPACE`), context and token deadlines (else `PIN_TOKEN_EXPIRED`), Ticket `expiresAtContextMs` (else `TICKET_INVALID`). An expired deadline **MUST** cause rejection; deadlines are never extended for a signature.
19. Compute `S` to obtain the 64-byte signature; self-verify it with actualPublic; on failure return `INTERNAL`.
20. KEL: commit atomically per §8.7. Non-KEL: no persistent write.
21. Return Signed: `{1:signature, 2:actualPublic, 3:originalDigest, 4:originalLength}`.

Any failed step zeroizes the signer, the parser and the whole context; when step 17 returns USER_ACTION_TIMEOUT, only the signer, parser and upload state are cleared and the context and token are kept (§10.2). The signature MUST NOT leave the authenticator in any form before step 20 completes.

### 7.8 Recover (0x46)

Retrieves the **original signature** of the slot's current latest key event. Only the current latest can be recovered; signatures of earlier events are obtained from the enterprise archive.

**Parameters:** `{1:slot, 2:originalDigest_b32, 254:2, 255:pinUvAuthParam_b32}`. **Required permission:** READ. **UP:** no. **Ticket:** none. **Result:** Signed (original signature).

The authenticator performs the following steps:

1. Authenticate per §8.1 (READ).
2. If slot is out of range, return `INVALID_PARAMETER`.
3. Read the slot's persistent state; if corrupted, return `RECOVERY_REQUIRED`; if not ACTIVE, return `NOT_FOUND`.
4. If `originalDigest ≠ latest.originalDigest`, return `NOT_FOUND`.
5. Confirm that the context and token are still valid and the transport is still connected.
6. Return `{1:latest.originalSignature, 2:actualPublic (= current current key), 3:latest.originalDigest, 4:latest.originalLength}`.

Recover is a read-only operation on stored state: it returns the stored signature without the message, UP or a new signing operation. A signature is public once published, and the authenticator stores the message digest, so a digest comparison suffices to identify the requested object; the platform still MUST verify the returned signature independently against its own copy of the message (§12.3).

### 7.9 Upload: UploadBegin (0x70) / UploadChunk (0x71) / UploadEnd (0x72)

When a message makes the complete Sign request exceed 2048 bytes, the platform MUST use the upload commands. Uploads serve Sign only and MUST complete in one continuous sequence within one context. The Ticket is carried in UploadBegin.

#### 7.9.1 UploadBegin (0x70)

**Parameters:** `{1:slot, 2:kind, 3:ticket_bstr, 254:2, 255:pinUvAuthParam_b32}`, i.e. the Sign parameters without original. **Required permission:** SIGN. **Result:** empty.

The authenticator performs the following steps:

1. If an upload is in progress, return `BUSY` (§7.0.1 step 2).
2. Authenticate per §8.1 (SIGN).
3. Execute §7.7 steps 2–9; declared length = the Ticket's `originalLength`.
4. Record the upload: owning context, slot, kind, declared length, received=0, Ticket verification result, transport and deadlines.
5. Return empty success.

#### 7.9.2 UploadChunk (0x71)

**Parameters:** `{1:offset, 2:bytes_bstr, 254:2, 255:pinUvAuthParam_b32}`; bytes is non-empty and the complete request is ≤ 2048 bytes. Authentication covers the offset and the chunk bytes. **Required permission:** SIGN.

The authenticator performs the following steps:

1. If no upload is in progress, return `UPLOAD_INVALID`.
2. Authenticate per §8.1 (SIGN).
3. If `offset ≠ received` or `offset + len(bytes) > declared length`, return `UPLOAD_INVALID`.
4. Feed bytes into the parser, digest and signer; an error detected immediately by the parser returns `INVALID_KERI_EVENT`.
5. received += len(bytes).
6. Return empty success.

Out-of-order chunks, overruns, authentication failures and any other failure zeroize the upload and the whole context; the platform MUST NOT automatically resend the same UploadChunk.

#### 7.9.3 UploadEnd (0x72)

**Parameters:** `{254:2, 255:pinUvAuthParam_b32}` (no business parameters). **Required permission:** SIGN. **Result:** Signed.

The authenticator performs the following steps:

1. As §7.9.2 steps 1–2.
2. Execute §7.7 steps 12–21.
3. Clear the upload state.

### 7.10 BindEnterprise (0x63)

Binds a factory-state device to an enterprise tenant and enterprise root key. The first binding fixes the enterprise root key; this command MUST be executed in a controlled environment (§12.5).

**Parameters:** `{1:tenant_b32, 2:enterpriseRoot_b32}`; no token authentication. **UP:** yes. **Result:** empty; the context is closed on success.

The authenticator performs the following steps:

1. Require a current context established by getKeyAgreement, otherwise `PUAT_REQUIRED`.
2. Validate the parameter key set and lengths.
3. If the lifecycle is not STOCK_UNBOUND, return `INVALID_STATE`.
4. enterpriseRoot MUST be a safe public key (canonical encoding, not small-order, in the prime-order subgroup) distinct from the attestation key; otherwise return `INVALID_PARAMETER`.
5. Collect one UP per §8.2.
6. Confirm that the context is still valid and the transport is still connected.
7. Atomically commit the binding record: tenant, enterpriseRoot, personalized=0.
8. Zeroize the context and return empty success.

The binding is permanent. The enterprise proves control of the enterprise root key at Personalize, through the TrustConfig signed with it.

### 7.11 Personalize (0x60)

Installs a TrustConfig signed by the enterprise root key and initializes four UNUSED slots.

**Parameters:** `{1:trustConfigEnvelope_bstr}` (≤ 1536 bytes); no token authentication. **UP:** yes. **Result:** empty; the context is closed on success.

The authenticator performs the following steps:

1. Require a current context, otherwise `PUAT_REQUIRED`.
2. If the lifecycle is not ENTERPRISE_BOUND, return `INVALID_STATE`.
3. Decode the envelope per §9.2; verify `"VHKP-TRUST\0" ‖ body` with the enterpriseRoot in the binding record; on failure return `TICKET_INVALID`.
4. Validate body: version 1; device, tenant and resetEpoch match this device; ownerMask, minPinChars and roles valid per §9.2 (keyIds in increasing byte order, public keys distinct from each other and from the enterprise root key and attestation key, safe public keys, capability bits only in the valid combinations of Appendix B). On mismatch return `TICKET_INVALID` or `INVALID_PARAMETER`.
5. Pre-check persistent storage space; if insufficient, return `NO_SPACE`.
6. Collect one UP per §8.2.
7. Confirm that the context is still valid and the transport is still connected.
8. Atomically commit: personalized=1 in the binding record, TrustConfig, four UNUSED slots.
9. After the write completes, zeroize the context and return empty success.

A configuration is installed once per reset epoch; changing role keys or configuration requires a full Reset.

### 7.12 Reset (0x07)

Makes employee secrets unrecoverable and enters a new reset epoch.

**Parameters:** none (command byte only, as in CTAP); no token authentication and no context required. **UP:** yes, a **5-second hold**. **Result:** empty.

Reset has the code, power-up window and UP requirement of CTAP authenticatorReset. It differs in that the enterprise binding and attestation identity are kept (§7.12.3) and the touch is held for 5 seconds.

#### 7.12.1 Authenticator Processing Steps

1. If the request carries any byte after the command byte, return `INVALID_LENGTH`.
2. If more than 10 000 ms have passed since this power-up, return `NOT_ALLOWED`.
3. If the lifecycle is not PERSONALIZED_NO_PIN or PIN_READY, return `INVALID_STATE`.
4. Determine the set of secrets to destroy: always the PIN record, all private keys of the four slots including pre-rotation historical keys, and all FIDO credentials (§7.13).
5. Collect one UP per §8.2 with **hold = 5000 ms**; on timeout return `USER_ACTION_TIMEOUT`.
6. Confirm that the transport is still connected (else `OPERATION_DENIED`).
7. Durably write the reset intent record: the binding record to be written in step 10 (tenant, enterpriseRoot, resetEpoch+1) and its digest. **From this step on, the Reset runs to completion and cannot be withdrawn.**
8. Make all secrets from step 4 unrecoverable, such that an attacker able to read the raw storage medium cannot reconstruct them; logical deletion, unlink or file system garbage collection does not satisfy this requirement. The authenticator MUST confirm that this step has completed before continuing.
9. Delete the PIN record, all state of the four slots, all FIDO credentials, and TrustConfig.
10. Atomically commit: resetEpoch+1, personalized=0; retain the attestation identity, tenant and enterpriseRoot.
11. Clear the reset intent record.
12. Zeroize any existing context and return empty success.

#### 7.12.2 Failure Semantics

- Any failure before step 7: no persistent change.
- Any failure or power loss after step 7: the Reset is completed at the next boot (§7.12.4).

#### 7.12.3 Scope of Reset

- Deactivating old AIDs on the network is the enterprise's responsibility (§12.7).
- Reset applies to all slots and all FIDO credentials together.
- After Reset the authenticator is in ENTERPRISE_BOUND; the new reset epoch requires Personalize only, with the existing binding.

#### 7.12.4 Completing Reset at Boot

At every boot, before reading other persistent state, the authenticator checks for a reset intent record:

1. If no reset intent record exists, boot normally.
2. If the reset intent record is complete and its digest is correct, execute §7.12.1 steps 8–11 and then boot normally. Steps 8–10 are idempotent.
3. If the reset intent record is incomplete or its digest does not match, clear the record and boot normally. In this case either the write of step 7 did not complete (persistent state is the pre-Reset state) or the clearing of step 11 did not complete (persistent state is the post-Reset state).

Completing Reset at boot requires neither UP nor a context.

### 7.13 Standard CTAP Operations

The authenticator is also a FIDO2 authenticator. It implements authenticatorMakeCredential (0x01), authenticatorGetAssertion (0x02), authenticatorGetNextAssertion (0x08) and authenticatorSelection (0x0B) as CTAP 2.3 defines them, together with GetInfo, ClientPIN and Reset above. It MAY implement further CTAP commands, such as authenticatorCredentialManagement (0x0A), as CTAP defines them.

These operations follow CTAP, with the following VCAP rules:

1. **Separate key material.** FIDO credentials are generated and stored separately from the four KERI slots. A FIDO credential key never signs through a VCAP command, and a slot key never signs through a CTAP operation.
2. **Lifecycle.** Standard operations are available in PERSONALIZED_NO_PIN and PIN_READY. In STOCK_UNBOUND and ENTERPRISE_BOUND they return `NOT_ALLOWED`; in RECOVERY_REQUIRED they return `RECOVERY_REQUIRED`.
3. **PIN and tokens.** The employee's single PIN serves both. A token obtained for CTAP permissions (`mc`, `ga`, …) authenticates CTAP operations as CTAP defines; a context whose token carries only CTAP permissions is never held (§5.3).
4. **User presence.** UP is collected per §8.2, so an NFC tap counts as one UP and a sensor press is required otherwise.
5. **Attestation.** Attestation for FIDO credentials MUST NOT use the VCAP attestation key, which identifies a single device. It uses batch attestation shared by a large population of devices, or self attestation.
6. **Reset.** Reset (§7.12) erases all FIDO credentials together with the KERI slots.

---

## 8. Common Authenticator Procedures

### 8.1 Verifying Command Authentication

Applies to every command carrying pinUvAuthProtocol (254) and pinUvAuthParam (255). Inputs: `command_u8`, the complete parameter map `P_full`, and the required permission `required`.

```
P    = the original deterministic CBOR map P_full without keys 254 and 255
msg  = "VHKP-CMD\0" ‖ contextId ‖ command_u8 ‖ H(CBOR(P))
pinUvAuthParam = HMAC-SHA256(token, msg)
```

The authenticator performs the following steps:

1. If no context exists, return `PUAT_REQUIRED`.
2. If pinUvAuthProtocol or pinUvAuthParam is missing, return `PUAT_REQUIRED`; if pinUvAuthProtocol ≠ 2, return `INVALID_PARAMETER`; if pinUvAuthParam is not 32 bytes, return `INVALID_LENGTH`.
3. If the context has no token, return `PUAT_REQUIRED`.
4. If the context has expired, or the token is unused and 19 800 ms have passed since issue, clear the token and return `PIN_TOKEN_EXPIRED`.
5. Compare pinUvAuthParam with `HMAC-SHA256(token, msg)` in constant time; on mismatch return `PIN_AUTH_INVALID` without executing the command.
6. If this is the token's first use, mark it as used (the initial usage time limit no longer applies).
7. If `required = 0` or `required ⊄ token.permissions`, return `OPERATION_DENIED`.
8. Return the command deadline `deadline = now + remaining context time`.

Notes:

- Replay protection comes from binding each command to contextId and the token; there is no separate session, sequence number or replay cache.
- Each UploadChunk is authenticated independently, so authentication covers its offset and bytes.
- Successful authentication shows only that the request comes from the platform holding the token; Ticket, UP and commit eligibility are checked separately.

### 8.2 Collecting User Presence (UP)

Inputs: `hold_ms` (0 for ordinary operations, 5000 for Reset), the current transport, and `deadline` (the result of §8.1 step 8; Reset has no context and no deadline).

The authenticator performs the following steps:

1. If the transport is NFC, `hold_ms` is 0, and the tap of the current field session has not been consumed (§11.3.5), mark it consumed and return success.
2. Turn on the presence indicator; turn it off however this procedure ends.
3. Record the start time `t0`. Let `hold = max(hold_ms, 30)`.
4. Loop until a result is reached:
   1. If the transport has been disconnected, return `OPERATION_DENIED`.
   2. If the transport reports a cancellation (`CTAPHID_CANCEL`, §11.2.3), return `KEEPALIVE_CANCEL`.
   3. If a `deadline` is set and has passed, return `PIN_TOKEN_EXPIRED`.
   4. If `now − t0 ≥ 30 000 ms`, stop waiting and return `USER_ACTION_TIMEOUT`.
   5. Release detection: a touch already held when the request starts does not count; the sensor MUST first be released and stay released for ≥ 30 ms.
   6. Press detection: a subsequent new press held for ≥ `hold` is accepted; a release before then returns to waiting for a press.
5. On acceptance, return success.

Rules:

- Each UP-requiring request consumes its own new sensor press or its own NFC tap. Over NFC one tap satisfies at most one request; a further UP-requiring request in the same field session needs a sensor press or a new tap. A press or tap is never latched or reused, and a signature is never retried automatically.
- Reset (`hold_ms` = 5000) always requires the sensor to be held; an NFC tap never satisfies it.
- While waiting, the authenticator stays in the current command and reports progress as the transport defines (CTAPHID keepalive, §11.2; NFC status polling, §11.3).
- The effective wait window is min(30 s, remaining context time). Sign / UploadEnd is itself a use of the token, so the UP wait is unaffected by the initial usage time limit. If the user does not touch within 30 s, `USER_ACTION_TIMEOUT` is returned and the token remains valid; the platform MAY start the signature again without asking for the PIN again.
- UP proves that someone present approved one operation; it does not prove that the user saw the message content. An NFC tap is a weaker signal than a sensor press, since it can also come from leaving the authenticator on the reader (§13.2).

### 8.3 Verifying a Ticket

Inputs: `ticket_bstr`, the request `kind`, the slot's persistent state, the current context, and TrustConfig.

The authenticator performs the following steps:

1. If `len(ticket) > 512`, return `INVALID_LENGTH`.
2. Decode `[body_bstr, keyId_tstr, signature_b64]` per §6.1.
3. Look up keyId in TrustConfig `roles`; if not found, return `TICKET_INVALID`.
4. Verify `"VHKP-SIGN\0" ‖ body_bstr` with that role public key; on failure return `TICKET_INVALID`.
5. Decode `body = [1, kind, signerKeyRef_b32, contextId_b32, originalDigest_b32, originalLength, expiresAtContextMs]`; if the version is not 1, return `INVALID_PARAMETER`.
6. If `body.kind ≠ request kind`, return `TICKET_INVALID`.
7. Let owner be the slot's owner; if the role's `capabilityMask` does not contain `bit(8·(owner−1) + (kind−1))`, return `TICKET_INVALID` (valid combinations in Appendix B).
8. If `contextId ≠ the contextId of the current context`, return `TICKET_INVALID`.
9. Compute KeyRef per §6.3 using the **actual signing public key** (old.next for ROT, current otherwise); if `signerKeyRef ≠ KeyRef`, return `TICKET_INVALID`.
10. If `originalLength ∉ 1..limit(kind)`, return `INVALID_LENGTH`.
11. Let `age = contextAgeMs`; unless `age < expiresAtContextMs ≤ min(age + 300 000, 600 000)`, return `TICKET_INVALID`.
12. Store the Ticket and its verification result, and compute `ticketDigest` for use in §8.6.

The Ticket binds the remaining facts indirectly. contextId fixes the authenticator, and with it the device, tenant, reset epoch and configuration (the enterprise checks these against a StateProof of the same context before issuing). KeyRef binds the device, reset epoch, slot, owner and actual signing key. The message digest, the length and the parser bind the AID, seq, said and prior.

Tickets carry no ticketId and the authenticator keeps no record of used Tickets. A non-KEL Ticket can be used for multiple signatures within the same context, so recipients MUST perform their own replay protection. A KEL Ticket becomes unusable once the slot commits its next event. Restarting an upload leaves `expiresAtContextMs` unchanged.

### 8.4 Key Event Checks

#### 8.4.1 Pre-BEGIN Checks

| kind | Slot condition | Signing key | Expected values |
|---|---|---|---|
| ICP | phase=CREATED; owner CLIENT or WORK | current | `s=0`; `d=i` |
| IXN | phase=ACTIVE | current | `s=latest.seq+1`; `p=latest.said`; `i=aid` |
| ROT | phase=ACTIVE; owner=WORK; prepared present | old.next | `s=latest.seq+1`; `p=latest.said`; `i=aid`; `k=[old.next]`; `n=[commit(newNext)]` |

- A slot condition mismatch returns `INVALID_STATE`; ROT without prepared returns `INVALID_STATE`.
- `latest.seq+1` MUST be checked for overflow.
- `p` is compared only with this slot's latest.

#### 8.4.2 Message Parsing

The authenticator performs the following checks while receiving the message (single pass):

1. The message is one complete JSON object within the length limit, with no duplicate top-level keys and no trailing bytes.
2. The size field of the version string `v` equals the total message length.
3. `t` equals the event type for the kind (`icp` / `ixn` / `rot`).
4. `d`, `i` and `p` (IXN / ROT) are 44 bytes with an `E` prefix and satisfy the expected values of §8.4.1.
5. `s` equals the expected sequence number.
6. ICP / ROT: `k` has exactly 1 entry, equal to the qb64 of the signing public key; `kt="1"`; `n` has exactly 1 entry, equal to the BLAKE3 digest commitment of the next key (next for ICP, newNext for ROT); `nt="1"`.
7. Delegated event types (`dip` / `drt`) are rejected.

A format or field mismatch returns `INVALID_KERI_EVENT`; a key, commitment or AID mismatch returns `KEY_BINDING`.

SAID computation, witnesses, delegation and network acceptance are verified in full by the enterprise (§12.8).

### 8.5 Non-KEL Format Checks

All non-KEL signatures use the current key of an ACTIVE slot and write no persistent state.

#### 8.5.1 EXN (kind 4, WORK)

Complete JSON; total length matches `v`; `t="exn"`; `i` equals this slot's AID. Route, recipients, attachments and business meaning are verified by the enterprise.

#### 8.5.2 RPY (kind 5, WORK)

Complete JSON; total length matches `v`; `t="rpy"`. Route, identity and business meaning are verified by the enterprise.

#### 8.5.3 AGENT (kind 6, CLIENT)

```
original = "VHKP-AGENT-SESSION\0" ‖ kind_u8 ‖ AID_raw44 ‖ body
body     = CBOR([1, receiver, nonce_b32, issued, expires, claims_bstr])
claims   = CBOR({1:walletProfile_tstr})   ; wallet operation profile identifier, verified by the enterprise
```

The authenticator checks: the domain separation tag, `kind_u8`, that `AID_raw44` equals this slot's AID, that the total length is ≤ 512 and equals the Ticket's originalLength, and the Ticket digest. The body is opaque to the authenticator; the enterprise verifies claims, receiver, nonce and `0 < expires − issued ≤ 300 s`.

The session authorizes only the reads defined by the wallet operation profile named in `claims`, plus contact modification / deletion, local credential deletion, OOBI resolution, identity renaming and marking notifications as read. It MUST NOT be used to sign KEL events, RPY or EXN on the user's behalf, or to perform Boot or administration.

### 8.6 Streaming Signature

1. Before receiving the first message byte: select seed `a` (and public key `A`), generate a random value from the RNG and combine it with `ticketDigest` to derive `r`, and compute `R = r·B`.
2. Feed the message chunk by chunk into the complete parser, `H(message)`, and the SHA-512 state of `H(R ‖ A ‖ message)`.
3. At END, obtain `k = H(R ‖ A ‖ message) mod L`.
4. **After UP**, compute `S = r + k·a mod L`; the signature is `R ‖ S`.
5. Self-verify the signature with `A`; on failure return `INTERNAL`.
6. The message is never written to persistent storage, and the authenticator keeps no copy of the complete message.

### 8.7 Atomic Commit

| Operation | Objects committed in one atomic commit |
|---|---|
| BindEnterprise | Binding record |
| Personalize | Binding record, TrustConfig, four UNUSED slots |
| CreateIdentity | The slot's keys and state |
| PrepareRotation | The slot's prepared entry (latest unchanged) |
| Sign ICP / IXN | The slot's latest (= this event, including the original signature) |
| Sign ROT | The slot's keys (current←old.next, next←newNext) and latest; prepared deleted |
| Reset | Reset intent record → secret destruction → new reset epoch → reset intent record cleared (§7.12) |
| GetState, Recover, non-KEL signatures | No business write |

Rules:

1. The written content is determined entirely inside the authenticator.
2. A signature or StateProof is returned only after the write completes.
3. After a ROT write, storage is in exactly one of two states: the pre-rotation keys, latest and prepared; or the post-rotation keys and latest (without prepared). Mixed intermediate states are impossible, and one rotation is applied at most once.
4. A write error or an error response **does not prove** that the write failed.
5. Slot state stores latest's kind, seq, said, originalLength, originalDigest and original signature for use by §7.8.
6. ROT is not required to destroy pre-rotation private keys; until Reset, an attacker able to read the raw storage medium may recover historical keys. Only Reset guarantees that they are unrecoverable (§13.1).

### 8.8 Zeroizing a Context

The authenticator performs the following steps:

1. Clear the fragment buffer and pending response.
2. Clear the upload, the signer (including `r` and seed copies) and the parser.
3. Clear the token, permissions, key agreement private key, shared secret and contextId.
4. Release the context's binding to its transport.

The persistent KEL head and prepared key are kept.

---

## 9. Data Structures

### 9.1 COSE_Key (P-256 key agreement)

```
COSE_Key = {1:2, 3:-25, -1:1, -2:x_b32, -3:y_b32}      ; kty=EC2, alg=ECDH-ES+HKDF-256, crv=P-256
```

### 9.2 TrustConfig

```
envelope = [body_bstr, rootSignature_b64]                  ; ≤ 1536 bytes
           ; rootSignature = Ed25519(enterpriseRoot, "VHKP-TRUST\0" ‖ body)
body     = [1, device_b32, tenant_b32, resetEpoch,
            ownerMask, minPinChars, roles]
role     = [keyId_tstr, capabilityMask, public_b32]
```

| Field | Constraint |
|---|---|
| ownerMask | Only bit0 (CLIENT) / bit1 (WORK); non-zero |
| minPinChars | 4..63 (an enterprise MAY choose 8 or more) |
| roles | 1..8 entries; keyId is 1..16 bytes of UTF-8, in strictly increasing byte order |
| role.public | Distinct from each other and from the enterprise root key and attestation key; safe public key (canonical encoding, not small-order, in the prime-order subgroup) |
| capabilityMask | Only the valid bits of Appendix B; non-zero |

### 9.3 Ticket

```
ticket = [body_bstr, keyId_tstr, signature_b64]            ; ≤ 512 bytes
         ; signature = Ed25519(role.public, "VHKP-SIGN\0" ‖ body)
body   = [1, kind, signerKeyRef_b32, contextId_b32,
          originalDigest_b32, originalLength, expiresAtContextMs]
```

| Field | Description |
|---|---|
| kind | 1..6 |
| signerKeyRef | §6.3, computed over the actual signing public key |
| contextId | The current getKeyAgreement context |
| originalDigest | H(message) |
| originalLength | 1..limit(kind) |
| expiresAtContextMs | Milliseconds since the start of the context (not wall-clock time); ≤ context age + 300 000 and ≤ 600 000 |

The enterprise computes `expiresAtContextMs = min(age₀ + locally elapsed time + T, 600 000)` with `T ≤ 300 000`. `age₀` is the contextAgeMs of a fresh StateProof, or the context age reported by the platform when there is no StateProof. The platform-reported age need not be trusted: at use the authenticator checks `age < expiresAtContextMs ≤ min(age + 300 000, 600 000)` (§8.3 step 11). Under-reporting only makes the Ticket expire earlier, and over-reporting causes the Ticket to be rejected. The usable window of any Ticket is therefore at most 300 000 ms, and every Ticket expires when its context ends.

### 9.4 StateProof

```
StateProof = {1:stateBody_bstr, 2:signature_b64}
             ; signature = Ed25519(attestation key, "VHKP-STATE\0" ‖ stateBody)
stateBody  = [1, device_b32, resetEpoch, configurationDigest_b32, contextId_b32,
              contextAgeMs, challenge_b32, authState, slots]           ; ≤ 1536 bytes
authState  = [pinRetries, powerCycleState(0/1), permissions, initialUsageRemainingMs, contextRemainingMs]
slots      = [slot0, slot1, slot2, slot3]
slot       = [index, owner, phase, currentPublic_b32/null, nextPublic_b32/null,
              preparedPublic_b32/null, aid_t44/null, head/null]
head       = [kind, seq, said_t44, originalLength, originalDigest_b32]
```

- All four slots are returned together in every StateProof.
- `preparedPublic` is the actual newNext; the existing next key signs the rot.
- `head.kind` is ICP, IXN or ROT and matches the owner. The original signature is retrieved with Recover.
- The platform computes KeyRef itself per §6.3.
- Verifiers verify a StateProof with the device's attestation public key registered at onboarding (§12.5 step 2).

### 9.5 Signed

```
Signed = {1:signature_b64, 2:actualPublic_b32, 3:originalDigest_b32, 4:originalLength}
```

Sign, UploadEnd and Recover use this same structure. The CESR index is always 0 and is encoded by the platform. The platform MUST verify the signature independently against its own copy of the message and the expected public key.

---

## 10. Status Codes

### 10.1 Status Code Table

Each status code corresponds to one action the platform can take. For VCAP commands, codes not listed MUST NOT be emitted; standard CTAP operations (§7.13) return CTAP status codes as CTAP defines; a platform receiving an unlisted code SHOULD report a protocol error and MUST NOT interpret it as a PIN error or as safe to retry. An error response is a single status byte with no map.

| Code | Name | Meaning | Platform action |
|---|---|---|---|
| 0x00 | OK | Success | If a result is present, verify its structure and signature / proof |
| 0x01 | INVALID_COMMAND | Unknown command or ClientPIN subcommand | Fix the implementation |
| 0x02 | INVALID_PARAMETER | Missing / extra keys, invalid combination, wrong fixed protocol number | Fix the request |
| 0x03 | INVALID_LENGTH | Length or integer out of range | Fix the request |
| 0x06 | BUSY | Another transport holds a held context, or an upload is in progress (CTAP1_ERR_CHANNEL_BUSY) | Wait and retry; any existing upload continues |
| 0x12 | INVALID_CBOR | Encoding, type, ordering, depth or trailing-byte violation | Fix the encoding |
| 0x14 | MISSING_PARAMETER | ClientPIN subcommand missing a required parameter | Fix the request |
| 0x27 | OPERATION_DENIED | Owner or permission denied; disconnection during UP; transport replaced during execution | Report as distinct from a PIN error; obtain the user's consent again |
| 0x28 | NO_SPACE | Insufficient persistent storage | Maintenance |
| 0x2d | KEEPALIVE_CANCEL | UP wait cancelled by `CTAPHID_CANCEL` | Do not re-sign automatically; reconcile per §12.3 if needed |
| 0x2f | USER_ACTION_TIMEOUT | UP wait timed out after 30 s (PIN_TOKEN_EXPIRED if the context deadline comes first) | Do not re-sign automatically |
| 0x30 | NOT_ALLOWED | Reset sent more than 10 s after power-up | Ask the user to reinsert or re-tap the authenticator and retry immediately |
| 0x31 | PIN_INVALID | Wrong PIN (attempt already decremented) | Show the balance from getPinRetries; the user retries |
| 0x32 | PIN_BLOCKED | PIN retry counter exhausted | Reset only |
| 0x33 | PIN_AUTH_INVALID | ClientPIN HMAC or command token authentication failed | Call getKeyAgreement again and obtain a token |
| 0x34 | PIN_AUTH_BLOCKED | 3 consecutive failures; power-cycle lockout | Continue after a power cycle; the persistent balance is not restored |
| 0x35 | PIN_NOT_SET | No PIN set | Guide the employee through setPIN |
| 0x36 | PUAT_REQUIRED | Missing context, token or authentication fields | Call getKeyAgreement / obtain a token first |
| 0x37 | PIN_POLICY_VIOLATION | New PIN violates the policy | Show the policy |
| 0x7f | INTERNAL | RNG, cryptographic engine or invariant failure | Stop and report |
| 0xf0 | INVALID_STATE | Lifecycle, slot or operation conditions not met | Query actual state with GetState |
| 0xf2 | NOT_FOUND | The slot has no latest event, or required data does not exist | Query actual state |
| 0xf3 | INVALID_KERI_EVENT | Message parsing or local KEL rules not satisfied | Check the message; for a KEL signature the head may be outdated: establish a new context, GetState, then request a new Ticket |
| 0xf4 | KEY_BINDING | Actual key, pre-rotation commitment or AID mismatch | Check the message; establish a new context, check the keys with GetState, then request a new Ticket |
| 0xf5 | TICKET_INVALID | Ticket signature / binding / deadline mismatch; also TrustConfig signature verification failure | Request a new Ticket, or query actual state |
| 0xf6 | RECOVERY_REQUIRED | Storage contains unrecognized or corrupted data | Offline maintenance |
| 0xf7 | UPLOAD_INVALID | Upload progress, final length / digest or phase error | Start over (new context) |
| 0xf8 | PIN_TOKEN_EXPIRED | Token or context deadline passed | Authorize again |

Codes below 0xF0 are CTAP status codes with their CTAP meaning (BUSY is CTAP1_ERR_CHANNEL_BUSY, NO_SPACE is CTAP2_ERR_KEY_STORE_FULL and INTERNAL is CTAP1_ERR_OTHER). Codes 0xF0 and 0xF2–0xF8 are VCAP-specific codes in the CTAP vendor range; 0xF1 is unassigned.

### 10.2 Context Zeroization on Error

Except for `BUSY` and the `USER_ACTION_TIMEOUT` of Sign / UploadEnd described below, an error MUST zeroize the whole context (§8.8) when any of the following holds:

1. An upload is in progress when the error occurs; or
2. The command is one of CreateIdentity, Sign, PrepareRotation, Personalize, BindEnterprise, Reset, UploadBegin / Chunk / End; or
3. The status code is one of PIN_INVALID, PIN_BLOCKED, PIN_AUTH_BLOCKED, PIN_AUTH_INVALID (except for ClientPIN subcommands), PIN_TOKEN_EXPIRED, INTERNAL, RECOVERY_REQUIRED, TICKET_INVALID, KEEPALIVE_CANCEL.

When Sign or UploadEnd returns USER_ACTION_TIMEOUT, the authenticator clears the signer, parser and upload state and keeps the context and token (§8.2). Other errors (for example `INVALID_PARAMETER` from GetState) keep the context. `BUSY` always keeps the current upload and context.

### 10.3 Ordinary Errors Are Not Proof

No status code is cryptographically authenticated. A platform MUST NOT automatically retry a PIN or re-sign on the basis of a status code, nor infer from one that a write did not occur.

---

## 11. Transport Bindings

VCAP messages are carried over the same transports as CTAP: CTAPHID over USB (§11.2) and ISO 7816-4 APDUs over NFC (§11.3). The message encoding (§11.1) is identical on both.

### 11.1 Message Encoding

```
request  = command_u8 ‖ CBOR(parameters_map)
response = status_u8 [‖ CBOR(result)]     ; result appended only when status=OK and a result exists
```

- A complete request and a complete response are each ≤ 2048 bytes.
- The message of a Sign request (≤ 16 384 bytes) is carried inline when the complete request is ≤ 2048 bytes, and otherwise through the upload commands of §7.9.
- A transport carries one request at a time. A new request arriving before the previous one completes is rejected by the transport (§11.2, §11.3) and is not executed.
- A transport-level success reports delivery only and is not proof of commitment. The business result is carried only in `status_u8` (Section 10).

**Lost responses.** When a response is lost on any transport, the platform **MUST NOT** automatically resend the whole command. It recovers per §12.3:

- KEL signature: new context → fresh GetState → Recover if needed.
- CreateIdentity / PrepareRotation: read the actual authenticator state with GetState and reconcile.
- PIN operations: query getPinRetries, then the user repeats the operation.
- Non-KEL signature: first query the enterprise for the consumption result of the request ID.

### 11.2 USB: CTAPHID

VCAP uses the CTAPHID binding of CTAP 2.3 unchanged. This section states only how it relates to VCAP.

#### 11.2.1 Packets and Messages

- The authenticator is a HID device with the FIDO usage page `0xF1D0`, usage `0x01`, and 64-byte input and output reports.
- An initialization packet is `CID(4) ‖ CMD(1, bit 7 set) ‖ BCNT(2, big-endian) ‖ DATA(57)`; a continuation packet is `CID(4) ‖ SEQ(1, 0..0x7F) ‖ DATA(59)`. A CTAPHID message is therefore at most 7609 bytes, which covers the 2048-byte VCAP request and response (§11.1).
- The authenticator MUST support `CTAPHID_PING` (0x01), `CTAPHID_INIT` (0x06), `CTAPHID_CBOR` (0x10), `CTAPHID_CANCEL` (0x11), `CTAPHID_KEEPALIVE` (0x3B) and `CTAPHID_ERROR` (0x3F). `CTAPHID_WINK` (0x08) is OPTIONAL. `CTAPHID_INIT` reports `CAPABILITY_CBOR`.

#### 11.2.2 Channels and Transports

- The platform obtains a channel identifier (CID) with `CTAPHID_INIT` on the broadcast channel `0xFFFFFFFF`. One CID is one transport in the sense of §3.1; a context belongs to the CID on which getKeyAgreement was sent.
- A `CTAPHID_INIT` on the CID that owns a context zeroizes that context. USB detachment zeroizes all contexts.
- While a CTAPHID transaction is in progress on one CID, a request on another CID receives `CTAPHID_ERROR` `ERR_CHANNEL_BUSY` (0x06). Once that transaction ends, a request from another CID while a held context exists receives the application status `BUSY` (0x06, §7.0.1 step 1); a context that is not held is zeroized and the request proceeds (§5.3).

#### 11.2.3 Requests and Responses

- A VCAP request (§11.1) is sent as the payload of `CTAPHID_CBOR`; the response payload is the VCAP response.
- While a command is executing, the authenticator sends `CTAPHID_KEEPALIVE` at least every 100 ms with status `STATUS_PROCESSING` (1), or `STATUS_UPNEEDED` (2) while it waits for UP (§8.2).
- `CTAPHID_CANCEL` on the CID of a command waiting for UP ends the wait: the command returns `KEEPALIVE_CANCEL` (§8.2 step 4.2), and the context is zeroized per §10.2. A `CTAPHID_CANCEL` with no pending command is ignored.
- CTAPHID framing errors are reported with `CTAPHID_ERROR` (`ERR_INVALID_CMD`, `ERR_INVALID_PAR`, `ERR_INVALID_LEN`, `ERR_INVALID_SEQ`, `ERR_MSG_TIMEOUT`, `ERR_INVALID_CHANNEL`, `ERR_OTHER`); no VCAP command is executed.

### 11.3 NFC: ISO 7816-4 APDU

VCAP uses the NFC binding of CTAP 2.3. This section states only how it relates to VCAP.

#### 11.3.1 Application Selection

- The authenticator uses the FIDO AID `A0 00 00 06 47 2F 00 01`.
- `SELECT = 00 A4 04 00 08 A0 00 00 06 47 2F 00 01 [00]`. Success returns the version string `FIDO_2_0` and `9000`.
- `SELECT` **MUST** zeroize the context, fragment buffer and pending response of the transport; no unknown outcome is carried over.

#### 11.3.2 Command Chaining and Response Retrieval

Only short APDUs are used.

**Sending (ISO 7816 command chaining):**

| Fragment | APDU | Notes |
|---|---|---|
| Not last | `90 10 00 00 Lc data [00]` | CLA bit 5 = 1 indicates the chain continues; data 1..255 bytes; returns `9000` only |
| Last | `80 10 P1 00 Lc data [00]` | `NFCCTAP_MSG`; the authenticator processes the request only after reassembling it completely. P1 = `80` indicates that the platform supports status polling (§11.3.5), otherwise `00` |

- Le, if present, MUST be `00`.
- The authenticator reassembles at most 2048 bytes; beyond that it returns `6700`. A reassembly failure executes no business operation.
- Ordering is guaranteed by the serial transport.

**Response:**

- The last fragment returns the first response fragment (≤ 256 bytes) and an SW.
- If data remains, SW = `61xx` and the platform retrieves the rest with `00 C0 00 00 Le`, where Le = SW2 (`00` means 256), until `9000`.
- `GET RESPONSE` reads the remaining response only; it does not re-execute the command.

#### 11.3.3 Status Words (SW)

| SW | Meaning |
|---|---|
| `9000` | Transport success (intermediate fragment or final response fragment) |
| `61xx` | Response data remaining, xx bytes (00 = 256) |
| `6700` | Wrong length or Le |
| `6985` | Conditions of use not satisfied (e.g. a new command starts while a command chain or pending response is incomplete) |
| `6A82` | Unknown AID |
| `6A86` | Incorrect P1 / P2 |
| `6D00` | Unknown INS |
| `6E00` | Unknown CLA |

#### 11.3.4 Serialization

A field carries one command chain or one pending response at a time. A new command arriving before the previous one completes returns `6985` and is not executed.

#### 11.3.5 Field Sessions, Status Polling and UP

- A **field session** begins when the authenticator is powered by the reader's field and ends when it leaves the field. The whole NFC field is one transport; leaving the field zeroizes all volatile state, including the context.
- **Tap as UP.** Entering the field counts as one user action. The first UP-requiring request in the field session consumes it (§8.2 step 1); later UP-requiring requests in the same session wait for a sensor press. Reset never accepts the tap.
- **Status polling.** When P1 of the last `NFCCTAP_MSG` fragment is `80` and the command cannot complete immediately (for example while waiting for a sensor press, or during a long upload step), the authenticator returns SW `9100` with one data byte, `STATUS_PROCESSING` (1) or `STATUS_UPNEEDED` (2). The platform then sends `NFCCTAP_GETRESPONSE` (`80 11 00 00 00`) until it receives the final response (`9000` or `61xx`). Each `9100` response repeats the current status. When P1 is `00`, the authenticator relies on ISO/IEC 14443-4 waiting-time extension (S(WTX)) to keep the reader waiting.
- **Cancellation.** Over NFC the platform cancels by ending the field session. A Cancel command (0x47) between two commands remains available.

#### 11.3.6 Leaving the Field During a Command

If the authenticator leaves the field before it returns a final response, the command ends with power loss. No signature leaves the authenticator. If the command had already committed persistent state (§8.7), the platform recovers per §12.3 in a new field session; the authenticator completes an interrupted Reset at the next power-up (§7.12.4).

---

## 12. Platform and Enterprise Procedures

This section specifies the steps that platforms and enterprises **MUST** follow when using the authenticator. The security of the authenticator depends on them: for example, non-KEL signature results are held only by the platform Outbox and the enterprise archive, so a lost response is recovered from there.

### 12.1 Establishing a Context and Authorization

The platform performs the following steps:

1. Open the transport: allocate a CTAPHID channel (§11.2), or `SELECT` the FIDO AID over NFC (§11.3).
2. Send ClientPIN getKeyAgreement to obtain the authenticator's keyAgreement; compute contextId per §6.3; generate a new ephemeral P-256 key as the platform keyAgreement for subsequent subcommands.
3. Ask the user for the PIN and request, in one call, all permissions the operation needs (for example `READ|SIGN` for signing) with getPinUvAuthTokenUsingPinWithPermissions.
4. Decrypt pinUvAuthToken to obtain the token. The PIN, pinHash, shared secret and token MUST NOT be logged; the PIN entered by the user MUST be cleared on completion, cancellation, backgrounding or unload.
5. When token permissions, device identity or slot state need confirmation, check `authState.permissions` and slot state with GetState (with a challenge); for a normal signature, decide per §12.2 step 2.
6. Reuse a valid token for subsequent commands; ask for the PIN again only after expiry, disconnection, permission escalation or revocation. A platform MUST NOT keep the token alive with idle background authentication or cache the PIN to renew it.

After a PIN error (`PIN_INVALID`) the context has been zeroized; the platform MUST restart from step 2, first showing the user the balance from getPinRetries, and MUST NOT retry automatically.

### 12.2 Normal Signature

1. Establish a context (§12.1) with permissions READ|SIGN. After getKeyAgreement the platform can compute contextId and perform step 3 in parallel with PIN entry.
2. Call GetState (with a challenge newly generated by the enterprise) to obtain a StateProof only when: this is the first contact with the device, the enterprise has no archived head for the slot, the outcome of the previous operation is unknown, or the enterprise requires it. Otherwise skip this step.
3. Submit the message, contextId and current context age (with the StateProof, if any) to the enterprise. The enterprise checks the state basis (§12.8 item 1), **durably stores the message first**, completes content approval, computes expiresAtContextMs per §9.3 and issues the Ticket.
4. The platform writes the message to the Outbox (durable storage before signing).
5. If `1 + len(CBOR({1..4,254,255})) ≤ 2048` bytes, use Sign; otherwise use UploadBegin, UploadChunk…, UploadEnd in sequence.
6. Prompt the user to touch once (over NFC, the tap counts as the touch).
7. On receiving Signed, verify the signature independently with the expected public key, and check that originalDigest and originalLength match the Outbox; for a KEL signature also check the expected head.
8. Archive to the enterprise; the UI shows "signed and archived".
9. Network publication and witness acceptance complete in the background; the UI shows "committed locally", "archived by enterprise", "accepted by network" and "business authorized" separately.

Consecutive signatures reuse the valid token and the archived head. The authenticator checks the KEL seq / prior and the actual key itself: if the head the enterprise relied on is outdated, Sign returns `INVALID_KERI_EVENT` or `KEY_BINDING` and outputs no signature. That error zeroizes the context and the user must enter the PIN again, so a platform in doubt about its local head SHOULD perform step 2 before requesting a Ticket.

### 12.3 Lost Response Recovery

The platform **MUST NOT** resend Sign, UploadEnd, CreateIdentity or PrepareRotation. It recovers as follows:

**KEL signatures (ICP / IXN / ROT):**

1. Establish a new context with permission READ.
2. GetState (new challenge); check whether the slot head is the expected seq / said / originalDigest, and check the actual keys (after ROT, current should be old.next).
3. If the head equals the expected event: obtain the message from the Outbox or from the enterprise (authorized retrieval by `(device, slot, said, originalDigest)`) → call Recover with `originalDigest` → verify the returned signature independently against the message → archive.
4. If the head is still the previous event, the earlier signature was not committed; the enterprise decides whether to issue a new Ticket, and the platform MUST NOT re-sign automatically.
5. If a later event already exists, obtain the original signature from the enterprise's historical archive.

**CreateIdentity / PrepareRotation:** check the slot's phase and current / next / prepared keys with GetState; the authenticator generates each key set only once.

**Non-KEL (EXN / RPY / AGENT):** results are not stored on the authenticator. First query the enterprise for the consumption result of the request ID; a lost response that was never archived cannot be recovered.

**PIN operations:** query getPinRetries; the user then repeats the operation.

### 12.4 Cancellation

1. When the user cancels while waiting for UP or during an upload, the platform disconnects the transport (or sends Cancel between two commands).
2. The authenticator zeroizes the context; prepared and committed heads are kept.
3. If a signature may have been committed, Cancel does not prove a rollback: reconcile read-only per §12.3.

### 12.5 Initial Onboarding (Factory to First Identity)

| Step | Actor | Authenticator command | UP |
|---|---|---|---|
| 1 | Manufacturer | Manufacturing tool creates STOCK, generates attestation identity and issues the certificate chain (offline) | — |
| 2 | Enterprise IT (controlled environment) | Verify the certificate chain and register the attestation public key → getKeyAgreement → BindEnterprise(tenant, enterprise root key) | 1 |
| 3 | Enterprise IT | getKeyAgreement → Personalize(TrustConfig) | 1 |
| 4 | Employee | getKeyAgreement → setPIN | 0 |
| 5 | Employee | getKeyAgreement → obtain token (READ\|MANAGE\|SIGN) → CreateIdentity(CLIENT) | 0 |
| 6 | Employee | GetState → enterprise issues Ticket → Sign(ICP, CLIENT) | 1 |
| 7 | Enterprise | Perform `/boot` with the archived CLIENT icp and its original signature (no additional device signature needed) | 0 |
| 8 | Employee | Sign(IXN, CLIENT): Agent approval | 1 |
| 9 | Employee | CreateIdentity(WORK) → Sign(ICP, WORK) | 1 |
| 10 | Employee | Sign(RPY, WORK): Agent end-role | 1 |
| 11 | Employee | Sign(AGENT, CLIENT): limited read/write session | 1 |

IT MUST NOT preset or upload employee private keys. In step 7, the enterprise SHOULD recheck the onboarding approval, employee, device and reset epoch, configuration and recipient, and durably record the onboarding operation before calling KERIA to prevent duplicate onboarding. If the response is lost, it reconciles read-only against the CLIENT ICP, the Agent DIP and the mutual ownership, and does not rebuild the Agent when material is missing.

### 12.6 Rotation (WORK)

1. Obtain a token (READ|SIGN).
2. PrepareRotation(slot, challenge) → StateProof; record preparedPublic (newNext). If prepared already exists, the same value is returned.
3. The platform constructs the rot: `k=[old.next]`, `n=[commit(newNext)]`, `s=latest.seq+1`, `p=latest.said`.
4. The enterprise issues a Ticket with `signerKeyRef = KeyRef(old.next)`.
5. Sign(ROT) / upload → one touch → after the authenticator commits, current=old.next, next=newNext, and prepared is deleted.
6. Recover from a lost response per §12.3.

### 12.7 Reset and the New Reset Epoch

1. The enterprise decides on a Reset (departure, lost device, blocked PIN, etc.) and, on the enterprise side, deactivates the old CLIENT / WORK AIDs and stops issuing Tickets for the old reset epoch. Reset also erases the employee's FIDO credentials, so relying parties that registered them need re-registration.
2. Reinsert or re-tap the authenticator and send Reset within 10 s of power-up; the user holds the touch for 5 seconds. No PIN is needed, so Reset also works after the PIN is blocked. Generic FIDO clients (browser or operating system settings) can also send Reset and prompt only for a touch; enterprise guidance SHOULD tell users that Reset requires a 5-second hold and erases all identities on the authenticator.
3. On success the authenticator returns to ENTERPRISE_BOUND (resetEpoch+1); IT personalizes again, and the employee sets a PIN and onboards again.
4. The authenticator SHOULD stay connected during Reset; if Reset is interrupted, the authenticator completes it at the next power-up.

### 12.8 Enterprise Ticket Issuance Requirements

The enterprise Ticket issuer MUST:

1. Use one of the following as the state basis:
   - a fresh StateProof obtained with a challenge **generated by the enterprise and used only once**;
   - the enterprise's archived head (archived original signature, or a head advanced by network acceptance), together with the contextId reported by the platform. For ICP the current / next keys come from the StateProof returned by CreateIdentity, and for ROT newNext comes from the StateProof returned by PrepareRotation.

   An incorrect platform-reported contextId makes the Ticket unusable, and the authenticator checks whether the head is current. Slot state cached by the wallet is never a state basis.
2. Durably store the message before issuing the Ticket; audit IDs stay within the enterprise.
3. Fully verify route, receiving domain, risk and content authorization; for KEL events also verify the SAID, prior event, witnesses, delegation and network acceptance.
4. Compute `expiresAtContextMs` per §9.3; when in doubt about device state, require the platform to submit a fresh StateProof.
5. Perform atomic replay protection for non-KEL results at the receiving end (Tickets are not consumed by the authenticator).
6. When an event is permanently rejected by an authority, mark the slot as REJECTED on the enterprise side only with operational authorization: no further Tickets are issued for the slot in this reset epoch, nothing is rolled back, and no replacement event is signed; the slot can be used again only after Reset. On transient failures, redeliver the original signature.

---

## 13. Security Considerations

### 13.1 Guarantees Provided by the Authenticator

| Threat | Guarantee | Assumptions and limits |
|---|---|---|
| Platform copies private keys through the normal interface | Keys are generated inside the authenticator and the interface has no export | Invasive physical extraction, fault injection and side channels are out of scope |
| Platform silently produces new signatures | Requires a SIGN token, a valid Ticket and a new UP | A touch or tap proves presence, not that the content was seen |
| Enterprise signs unilaterally | Role keys only issue Tickets; signing requires the in-authenticator private key and UP | Relies on trusted firmware |
| Employee bypasses enterprise policy | No Ticket, no signature | |
| Rotation to a platform-generated key | k / n / newNext are constrained to in-authenticator keys, and rot is signed with the in-authenticator old.next | Covers rotation only; other forms of long-term takeover are addressed by the enterprise controls of §12.8 |
| Fork within a slot | Events advance strictly by seq / prior, are written before being returned, and latest can only be retrieved as its original signature | Assumes no full rollback of non-volatile storage |
| Duplicate signature after a lost response | KEL: Recover; non-KEL: Outbox and request ID | |
| Lost device / employee departure | Reset makes the PIN record and all private keys unrecoverable; the enterprise deactivates old AIDs | Network deactivation, secret destruction and external copies are separate matters; historical keys may persist after ROT until Reset |

### 13.2 Remaining Risks

1. **Induced signing:** UP confirms presence only, so the authenticator cannot tell whether the user was induced to sign a well-formed but malicious message. Independent enterprise approval of the message, recipients, attachments, route, receiving domain and deadline is required.
2. **Ticket reuse:** a non-KEL Ticket can be used for multiple signatures within the same context; recipients MUST perform their own replay protection.
3. **Ticket lifetime without a StateProof:** when the enterprise issues a Ticket based on the platform-reported context age, the Ticket's usable window is still at most 300 s, but the time from issue to expiry can extend to the end of the context (≤ 600 s). Operations that need a tighter deadline SHOULD require a fresh StateProof.
4. **NFC tap as UP:** over NFC the tap satisfies UP for one request per field session. A compromised platform that holds a valid PIN token and Ticket can use the user's next tap for its own request, just as it can use a sensor press; a tap also happens when the authenticator is left on a reader. Enterprise approval of the message content remains the control.
5. **FIDO credentials:** the authenticator also holds FIDO credentials for WebAuthn sign-in. They share the PIN and the device but not keys or attestation with VCAP (§7.13), so a relying party cannot link a FIDO credential to the device's VCAP attestation identity.

### 13.3 PIN

- The PIN is transmitted only encrypted under pinUvAuthProtocol 2; the authenticator stores only a 16-byte check value and the remaining attempt count (persistent across power loss), and stores neither the PIN nor the token.
- An attempt is decremented before comparison and the counter is restored on success; power loss does not refund an attempt.

### 13.4 Random Numbers

All random values, contextIds, tokens, key agreement private keys and seeds come from a health-tested RNG; an RNG failure returns `INTERNAL` and closes the context. The signature nonce mixes in the digest of the signed object to limit the consequences of RNG bias.

---

## Appendix A Constants

| Constant | Value |
|---|---|
| NFC AID | `A0 00 00 06 47 2F 00 01` (FIDO) |
| Complete request / response limit | 2048 bytes |
| Short APDU data | 1..255 bytes; first response fragment ≤ 256 bytes |
| KERI message limit (kind 1..5) | 16 384 bytes |
| AGENT message limit (kind 6) | 512 bytes |
| Ticket | ≤ 512 bytes |
| TrustConfig envelope | ≤ 1536 bytes |
| stateBody | ≤ 1536 bytes |
| Maximum context lifetime | 600 000 ms |
| Token initial usage time limit | 19 800 ms |
| Token maximum usage period | 600 000 ms (same as the context) |
| Maximum Ticket validity | Context age at issue + 300 000 ms, and ≤ 600 000 ms |
| UP wait timeout | 30 000 ms |
| Reset power-up window | 10 000 ms |
| UP debounce (release) | 30 ms |
| UP hold duration | Ordinary 30 ms (hold 0); Reset 5000 ms |
| NFC tap as UP | At most one UP-requiring request per field session; never for Reset |
| PIN retry counter | 8 |
| PIN consecutive-failure power-cycle lockout | 3 |
| PIN length | 1..63 bytes; minPinChars 4..63 |
| Number of slots | 4 |
| TrustConfig roles | 1..8; keyId 1..16 bytes |
| CBOR depth / item count | ≤ 16 / ≤ 1024 |
| VCAP permission bits | READ=0x0100, SIGN=0x0200, MANAGE=0x0400 |
| owner | CLIENT=1, WORK=2 |
| phase | UNUSED=0, CREATED=1, ACTIVE=2 |

## Appendix B Role Capability Bits

`bit = 8·(owner−1) + (kind−1)`

| owner | kind | Bit | Mask | Role class |
|---|---|---:|---|---|
| CLIENT | ICP | 0 | `0x0001` | KEL |
| CLIENT | IXN | 1 | `0x0002` | KEL |
| CLIENT | AGENT | 5 | `0x0020` | Message |
| WORK | ICP | 8 | `0x0100` | KEL |
| WORK | IXN | 9 | `0x0200` | KEL |
| WORK | ROT | 10 | `0x0400` | KEL |
| WORK | EXN | 11 | `0x0800` | Message |
| WORK | RPY | 12 | `0x1000` | Message |

All valid bits: `0x1F23` (8 capabilities); message role bits: `0x1820`. Any other bit (e.g. CLIENT ROT, WORK AGENT) is invalid; a capabilityMask containing an invalid bit, or equal to zero, causes Personalize to fail.

## Appendix C References

- FIDO Alliance, Client to Authenticator Protocol (CTAP) 2.3: command codes, authenticatorGetInfo, authenticatorClientPIN, authenticatorReset, CTAPHID and NFC bindings
- W3C Web Authentication Level 3
- RFC 2119: Key words for use in RFCs to Indicate Requirement Levels
- RFC 8949: Concise Binary Object Representation (CBOR), §4.2 Deterministically Encoded CBOR
- RFC 8152 / RFC 9052: CBOR Object Signing and Encryption (COSE) Key
- RFC 8032: Edwards-Curve Digital Signature Algorithm (EdDSA)
- RFC 5869: HMAC-based Extract-and-Expand Key Derivation Function (HKDF)
- FIPS 180-4 (SHA-256 / SHA-512), FIPS 197 (AES), SP 800-38A (CBC)
- SEC 1 / FIPS 186-5: P-256 elliptic curve
- RFC 9053: COSE Initial Algorithms (EC2 key type and P-256 curve identifier)
- ISO/IEC 7816-4: command chaining, GET RESPONSE and status words
- KERI (Key Event Receipt Infrastructure) specification: event format, SAID, pre-rotation commitment
- BLAKE3 specification

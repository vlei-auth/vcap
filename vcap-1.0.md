# vLEI Client to Authenticator Protocol (VCAP) 1.0

*Editor's Draft — 2 November 2026*

**Specification identifier:** VCAP-1.0  
**Editor's Draft URL:** https://vlei-auth.github.io/vcap/  
**Status:** Editor's Draft  
**Editors:**
  * Fan Dang (ACentauri Technology Limited)

**Companion documents:** [VAF 1.0](https://vlei-auth.github.io/vaf/), [VCAP-EI 1.0](https://vlei-auth.github.io/vcap-ei/)

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
- Appendix D Attestation Certificate Chain and Enrollment Records
- Appendix E Test Vectors

---

## 1. Introduction

### 1.1 Purpose

The vLEI Key is a personal KERI signing device with a touch sensor. An employee's KERI private keys exist only inside the authenticator.

Because both the platform running the wallet and the enterprise services may be compromised, the following five rules are enforced by the authenticator itself:

1. **Private keys stay in the authenticator.** The PIN failure count is kept in the authenticator and survives power loss. Every signature requires one deliberate user action (user presence, UP): a press of the touch sensor, or over NFC the tap that brings the authenticator into the reader's field.
2. **Every signature is authorized by the enterprise.** Each signature requires a Ticket issued by an enterprise role key. The Ticket specifies the slot's next signature counter, the signing key, and the digest and length of the message to be signed; each Ticket is usable for exactly one signature.
3. **Rotation stays within authenticator-generated keys.** The current key and next key in `icp` MUST be two keys generated inside the authenticator. A `rot` MUST be signed with the previously committed next key, and the newly committed next key MUST be freshly generated inside the authenticator. Even if the platform and the enterprise services are both compromised, an attacker therefore cannot rotate the identity to a key outside the authenticator.
4. **Events advance one at a time.** Events in a slot advance strictly in sequence (sequence number `s` incremented by 1, `p` referencing the previous event), so with intact persistent storage each slot produces at most one event per sequence number.
5. **Each signature is committed once.** A signature is durably committed in the authenticator before it is returned to the platform. The signature of the latest key event and the most recent signature of the slot remain retrievable with Recover, so a lost response yields the original signature rather than a new one. The authenticator stores no message. After a successful Reset, the PIN record and all private keys of the old reset epoch are unrecoverable.

This document specifies the authenticator state model, the parameters and processing algorithm of each command, data structures and status codes, for use by firmware implementers, wallets, enterprise services and external auditors.

### 1.2 Scope

This document defines the interface between the authenticator and the platform, and the format of enterprise-signed objects consumed by the authenticator. The internal protocols of enterprise gateways, KERIA, witnesses and wallets are out of scope; Section 12 states only their requirements for using authenticator output. The interface between platforms and the enterprise service (Ticket requests, archiving and recovery) is specified by the companion [VCAP Enterprise Interface 1.0](https://vlei-auth.github.io/vcap-ei/).

The VCAP operations are reachable as native CTAP vendor commands (§7.4–§7.12) over the transports of Section 11. An authenticator MAY in addition implement the WebAuthn route (§7.14), through which a web page invokes the same operations with standard WebAuthn calls; both routes apply the same checks and commit the same state.

---

## 2. Conformance

The key words "**MUST**", "**MUST NOT**", "**REQUIRED**", "**SHOULD**", "**SHOULD NOT**", "**RECOMMENDED**" and "**MAY**" in this document are to be interpreted as described in BCP 14 [RFC 2119] [RFC 8174] when, and only when, they appear in all capitals, as shown here.

### 2.1 Conformance Classes

| Class | Implements | Sections that apply |
|---|---|---|
| **Authenticator** | Firmware and hardware of the vLEI Key | §§ 5–11, Appendices A and B; §7.14 when the WebAuthn route is implemented |
| **Platform** | Software that sends VCAP commands: wallets, IT tools, manufacturing tools | §§ 6, 9, 10, 11 (as sender) and 12.1–12.7 |
| **Web platform** | An enterprise web page using the WebAuthn route | §§ 7.14, 12.9 |
| **Enterprise service** | Ticket issuer, archive and enrollment service | §§ 6, 9, 12.5, 12.7–12.9, Appendix D |
| **Manufacturer** | Producer of the attestation identity | Appendix D.1, D.3 |

An Authenticator implements at least one transport of Section 11 and declares in GetInfo `transports` exactly the transports it implements (§7.1). The following features are optional; an Authenticator that implements one implements all of its requirements:

| Feature | Sections |
|---|---|
| USB HID transport | §11.2 |
| NFC transport | §11.3 |
| USB CCID transport | §11.4 |
| WebAuthn route | §7.14 |

### 2.2 Normative Statements

- Numbered algorithms introduced with "The authenticator performs the following steps" are normative: the externally observable behavior of the authenticator (the status code returned, whether state is written, whether output is produced) MUST equal the result of executing those steps in order.
- **Error precedence is unspecified.** When a request violates several conditions, the authenticator MAY return any of the corresponding errors; platforms MUST NOT base decisions on error precedence.
- State-machine tables, transition tables and "Constraints" or "Rules" lists are normative for the Authenticator.
- A platform determines whether an operation was committed only from a verified Signed or StateProof (§12.3); status codes carry no cryptographic evidence.

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
| transport | One logical link: one CTAPHID channel over USB HID, one NFC field session, or one CCID card session (§11.4) |
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
| Ticket | A signing authorization object issued by the Ticket issuer (VCAP, §9.2) |
| TrustConfig | Device configuration signed by the enterprise root key (VCAP, §9.1) |
| StateProof | Authenticator state signed by the attestation key (VCAP, §9.3) |
| reset epoch (`resetEpoch`) | A counter incremented by 1 after each successful Reset |
| atomic commit | A set of persistent writes that take effect entirely or not at all |
| reset intent record | A record durably written by Reset before secrets are destroyed, used to complete the Reset at the next boot after a power loss |
| domain separation tag | A fixed string prepended to a signature or MAC input to distinguish its purpose |
| zeroize | Clear and invalidate volatile secrets and state |
| safe public key | An Ed25519 public key in canonical encoding that is not a small-order point and lies in the prime-order subgroup |
| challenge | A single-use 32-byte random value generated by a verifier to establish the freshness of a StateProof |
| initial usage time limit | The time within which a token MUST be first used to authenticate a command after it is issued |
| power-cycle lockout | After a threshold of consecutive PIN failures, further verification requires a power cycle |
| PIN retry counter | The durably stored number of remaining PIN attempts |
| signature counter (`signCounter`) | A persistent per-slot counter advanced by every signature; each Ticket names the value its signature will receive (§5.2) |
| slot handle | The credential ID that names a slot on the WebAuthn route (§7.14.3) |
| field session | The period an NFC authenticator is powered by one reader field (§11.3) |
| card session | The period from a CCID ICC power-on to the matching power-off (§11.4) |
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

Authenticator (attestation key, 4 slots) ◀─CTAPHID / NFC / CCID─▶ Platform (wallet) ◀─HTTPS─▶ Ticket issuer / gateway ──▶ KERIA / witnesses / recipients
```

- The authenticator trusts only: its own attestation identity, the enterprise root key bound by BindEnterprise, the TrustConfig role keys installed under a signature of the enterprise root key, and the employee's PIN and touch.
- The platform is untrusted: it can block, reorder and observe the link, and can send any command with a valid token. A new signature still requires an enterprise Ticket and a new UP, and every rotation stays within keys inside the authenticator.
- The enterprise cannot sign alone: role keys only issue Tickets, and a signature requires the employee's PIN authorization and a physical user action.

### 4.2 Lifecycle Overview

```
Manufacturing: STOCK initialization ──> STOCK_UNBOUND
   │ BindEnterprise (tenant + enterprise root public key + UP, during enrollment)
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
  |-- message ----------------------------------------------------------->|  store message, approve
  |<-- Ticket (slot's next signCounter) ----------------------------------|
  |   write message to Outbox        |                                    |
  |-- open transport --------------->|                                    |
  |-- getKeyAgreement -------------->|  new P-256 key and contextId
  |-- getPinUvAuthToken...(SIGN) --->|  decrement, compare PIN, reset to 8 on success
  |<-- pinUvAuthToken ---------------|                                    |
  |-- Sign / Upload* --------------->|  verify Ticket, parse, wait for UP
  |                                  |  (user touches once), sign, self-verify, commit
  |<-- Signed (incl. signCounter) ---|                                    |
  |   verify signature, archive ---------------------------------------->|
```

The enterprise approves based on its archived head and signature counter, so the Ticket can be obtained before the authenticator is connected, and a normal signature takes one business exchange with the authenticator (Sign). When the enterprise has no usable state or an earlier outcome is unknown, the platform first calls GetState with an enterprise-generated challenge and submits the resulting StateProof (§12.2).

---

## 5. Authenticator State Model

Authenticator state consists of **persistent state** (lifecycle, four slots, PIN record, reset intent record) and **volatile state** (context, token, upload, power-cycle lockout count, power-up time).

### 5.1 Device Lifecycle

The `lifecycle` field of status-mode GetState (§7.4.1) reports the following values:

| Value | Name | Meaning |
|---:|---|---|
| 0 | STOCK_UNBOUND | Not bound to an enterprise |
| 1 | ENTERPRISE_BOUND | Bound to a tenant and enterprise root key; not personalized in this reset epoch |
| 2 | PERSONALIZED_NO_PIN | TrustConfig and four UNUSED slots installed; no PIN set |
| 3 | PIN_READY | Personalized and PIN set (says nothing about lockout; retry state is reported by ClientPIN) |
| 4 | RECOVERY_REQUIRED | Storage contains unrecognized or corrupted data |

Transitions:

| Current | Event | Next | Condition |
|---|---|---|---|
| — | Manufacturer STOCK initialization | STOCK_UNBOUND | Created only by an explicit manufacturing procedure; a normal boot MUST NOT treat unrecognized storage as an empty device and format it |
| STOCK_UNBOUND | BindEnterprise succeeds | ENTERPRISE_BOUND | §7.10 |
| ENTERPRISE_BOUND | Personalize succeeds | PERSONALIZED_NO_PIN, or PIN_READY if a PIN is already set | §7.11 |
| PERSONALIZED_NO_PIN | setPIN succeeds | PIN_READY | §7.2 |
| STOCK_UNBOUND | Reset succeeds | STOCK_UNBOUND | §7.12 |
| ENTERPRISE_BOUND / PERSONALIZED_NO_PIN / PIN_READY | Reset succeeds | ENTERPRISE_BOUND (resetEpoch+1) | §7.12; tenant and enterprise root key retained |
| Any | Unrecognized or corrupted data found at boot | RECOVERY_REQUIRED | The affected data is retained until Reset |
| RECOVERY_REQUIRED | Reset succeeds | ENTERPRISE_BOUND (resetEpoch+1) | §7.12; requires a readable binding record and attestation identity |
| Any | Valid reset intent record found at boot | ENTERPRISE_BOUND (resetEpoch+1) | Reset completed at boot (§7.12.4) |

Constraints:

- The binding is permanent: a bound authenticator cannot be rebound or returned to the factory state.
- Missing data **MUST NOT** be treated as UNUSED or not personalized; if `personalized=1` and the configuration or a slot record is missing, the authenticator MUST treat it as corruption.
- The PIN and FIDO credentials (§7.13) are independent of the lifecycle: a PIN can be set and FIDO credentials created in any lifecycle state other than RECOVERY_REQUIRED.
- In `RECOVERY_REQUIRED`, every command except `GetInfo`, status-mode `GetState`, `Cancel` and `Reset` (including ClientPIN) returns `RECOVERY_REQUIRED`. Reset is the user's way out of this state (§7.12).

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

| phase | owner | current / next | prepared | aid / head | signCounter | lastSigned |
|---|---|---|---|---|---|---|
| UNUSED | 0 | null | null | null | 0 | null |
| CREATED | 1 or 2 | present | null | null | 0 | null |
| ACTIVE | 1 or 2 | present | WORK only, optional | present | ≥ 1 | present |

- Any mix of owners is permitted, including four WORK slots. Slots are independent of one another and hold no receipts or pending events. A slot keeps its identity until Reset, which returns all slots to UNUSED together.
- A CLIENT slot permits ICP / IXN / AGENT; a WORK slot permits ICP / IXN / ROT / EXN / RPY.
- When `prepared` exists, a further PrepareRotation returns the existing preparation unchanged.
- `signCounter` is a persistent per-slot signature counter. It starts at 0 and is incremented by one in the atomic commit of every signature of any kind (§8.7); it never decreases within a reset epoch. Each Ticket names the counter value its signature will receive (§9.2), so each Ticket is usable once.

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
- **Zeroization events:** transport disconnection, `SELECT` of the FIDO AID over NFC or CCID, CCID ICC power-off, `CTAPHID_CANCEL`, the `Cancel` command, context expiry, token expiry detected, authentication or integrity failure, successful BindEnterprise / Personalize / Reset, and the errors listed in §10.2. Zeroization clears the fragment buffer, pending response, upload and signer, parser, token, P-256 key agreement key and contextId. The persistent KEL head and prepared key are kept.

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

All CBOR of VCAP commands (§7.2–§7.12) and of VCAP data structures MUST satisfy the rules below. Standard CTAP operations (§7.13), including VCAP-wrapped requests (§7.14), and the CTAP parameters of ClientPIN follow the CTAP CBOR encoding rules instead, so that generic clients interoperate; the VCAP payloads they carry (`user.id`, VCAPREQ) follow the rules below.

1. Integers and lengths use the shortest definite-length encoding; indefinite-length encoding MUST NOT be used.
2. A tstr MUST be valid UTF-8.
3. Tags, floating-point numbers, simple values (`null` only where explicitly permitted by this document) and trailing bytes MUST NOT appear.
4. Nesting depth ≤ 16, and ≤ 1024 data items in total, counting every nested item, map key and map value.
5. Keys of ordinary maps MUST be unsigned integers in strictly increasing order.
6. Unknown, missing and extra keys are all rejected.

Violations of items 1–4 return `INVALID_CBOR`; key-set violations of items 5 and 6 return `INVALID_PARAMETER`; out-of-range lengths or integers return `INVALID_LENGTH`.

### 6.2 Byte Conventions

- All fixed-width integers are big-endian unsigned.
- Signatures are 64-byte `R‖S`; public keys are 32-byte compressed Ed25519 points.
- AID, SAID and prior are 44-byte KERI qb64 text beginning with `E` (BLAKE3-256 digest code).
- `qb64(code, raw32)` is the 44-character KERI qb64 text of a 32-byte value: `code ‖ B[1..43]`, where `B` is the unpadded base64url encoding (44 characters) of `0x00 ‖ raw32` and `B[1..43]` drops its first character.
- In KERI events, a slot public key appears as `qb64("D", pub)` (transferable Ed25519 verification key).
- The next-key commitment is `commit(pub) = qb64("E", BLAKE3-256(qb64("D", pub)))`: the BLAKE3-256 digest of the 44 ASCII bytes of the key's qb64 text.

### 6.3 Identifier Derivation

```
device     = H("VCAP-DEVICE-ID\0" ‖ attestationPublic_raw32)
tenant     = H(UTF-8 encoding of the enterprise identifier)   ; see below
configurationDigest = H(complete TrustConfig envelope)
KeyRef     = H("VCAP-KEYREF\0" ‖ device ‖ resetEpoch_BE8 ‖ CBOR([slot, owner]) ‖ actualPublic_raw32)
contextId  = H("VCAP-CONTEXT\0" ‖ keyAgreement.x)   ; the authenticator's keyAgreement
```

The enterprise identifier is a string chosen by the enterprise: 1..128 bytes of UTF-8 in Unicode Normalization Form C. An enterprise that has an LEI SHOULD use its LEI (ISO 17442: 20 uppercase alphanumeric characters).

`actualPublic` is **the public key actually used for this signature**: current for ICP / IXN / EXN / RPY / AGENT, and old.next for ROT. The authenticator computes KeyRef from its own verified slot state and MUST NOT use a KeyRef or digest supplied by the platform.

### 6.4 Cryptographic Primitives

| Purpose | Algorithm | Notes |
|---|---|---|
| Business signatures, attestation signatures | Ed25519 (RFC 8032) | Any computation that yields signatures verifying under RFC 8032 conforms (§8.6). Verification rules below. Public keys received from outside MUST be safe public keys (§3.1) |
| Digest | SHA-256 | |
| KERI next key commitment / E encoding | BLAKE3-256 | As defined by KERI |
| PIN protocol | [CTAP PIN/UV Auth Protocol Two][ctap-pinproto2] (P-256 ECDH, HKDF-SHA-256, AES-256-CBC, HMAC-SHA-256) | §7.2 |

Each purpose has one fixed algorithm; algorithms are not negotiated.

**Ed25519 verification.** Every party that verifies a VCAP signature (the authenticator for TrustConfig and Tickets; platforms and enterprises for StateProof, Signed and `deviceSig`) MUST verify per RFC 8032 §5.1.7 with these additional rules, so that all implementations accept exactly the same signatures:

1. `S` MUST be less than the group order `L`; otherwise the signature is invalid.
2. `R` and the public key `A` MUST be canonical encodings of points; `A` MUST be a safe public key.
3. The cofactorless equation `[S]B = R + [k]A` is used.

**KERI encoding.** VCAP 1.0 signs KERI 1.0 events in JSON serialization only (version string `KERI10JSON`); §8.4.3 defines the accepted event syntax.

### 6.5 Signature Domains

Each signed object uses a unique domain separation tag. Verifiers MUST use the prefixes below byte for byte.

| Domain separation tag | Signer | Signed content | Definition |
|---|---|---|---|
| `"VCAP-STATE\0"` | Attestation key | `stateBody` bytes | §9.3 |
| `"VCAP-TRUST\0"` | Enterprise root key | TrustConfig `body` bytes | §9.1 |
| `"VCAP-SIGN\0"` | TrustConfig role key | Ticket `body` bytes | §9.2 |
| `"VCAP-CMD\0"` | HMAC(token) | Command authentication message | §8.1 |
| `"VCAP-AGENT-SESSION\0"` | Slot current key (kind 6) | AGENT message prefix | §8.5.3 |
| `"VCAP-WEBAUTHN\0"` | Attestation key | WebAuthn-wrapped result | §7.14.5 |
| `"VCAP-HANDLE\0"` | HMAC(handleKey) | Slot handle | §7.14.3 |
| (no prefix) | Slot key | KERI message | §8.4, §8.5 |

---

## 7. Authenticator API

### 7.0 Command Table

Command codes `0x00`–`0x3F` are the [CTAP command codes][ctap-commands] and are used only for commands whose function is the same as the CTAP command. VCAP-specific commands use the CTAP vendor command range `0x40`–`0xBF`, avoiding `0x40` and `0x41`, which CTAP 2.3 keeps for the prototype authenticatorBioEnrollment and authenticatorCredentialManagement commands. The authenticator also implements the standard CTAP authenticator operations (§7.13), so it serves as a FIDO2 security key for WebAuthn.

| Code | Command | Business parameters (excluding pinUvAuthProtocol / pinUvAuthParam) | Token permission | UP | Result | Context closed on success |
|---|---|---|---|---|---|---|
| 0x01 | authenticatorMakeCredential | As CTAP (§7.13); VCAP-wrapped CreateIdentity (§7.14) | CTAP `mc` | **Yes** | As CTAP | No |
| 0x02 | authenticatorGetAssertion | As CTAP (§7.13); VCAP-wrapped operations (§7.14) | CTAP `ga` | **Yes** | As CTAP | No |
| 0x04 | GetInfo | none | None (public) | No | authenticatorGetInfo map (§7.1) | No |
| 0x06 | ClientPIN | See §7.2 | None (self-authenticating) | No | See §7.2 | No |
| 0x07 | Reset | none | None; within 10 s of power-up | **Yes (5 s hold)** | Empty | Yes |
| 0x08 | authenticatorGetNextAssertion | As CTAP (§7.13) | — | No | As CTAP | No |
| 0x0B | authenticatorSelection | As CTAP (§7.13) | None | **Yes** | As CTAP | No |
| 0x50 | GetState | Status mode: `{}`; proof mode: `{1:challenge_b32}` | Status mode: none (public); proof mode: READ | No | Status mode: `{1:lifecycle}`; proof mode: StateProof | No |
| 0x51 | CreateIdentity | `{1:slot,2:owner,3:challenge_b32}` | READ+MANAGE | No | StateProof | No |
| 0x53 | Sign | `{1:slot,2:kind,3:ticket_bstr,4:original_bstr}` | SIGN | **Yes** | Signed | No |
| 0x54 | PrepareRotation | `{1:slot,2:challenge_b32}` | READ+SIGN | No | StateProof | No |
| 0x56 | Recover | `{1:slot,2:originalDigest_b32}` | READ | No | Signed (original signature) | No |
| 0x57 | Cancel | `{}` | None (owning transport only) | No | Empty | Yes |
| 0x60 | Personalize | `{1:trustConfigEnvelope_bstr}` | None; requires context + enterprise root signature | **Yes** | Empty | Yes |
| 0x63 | BindEnterprise | `{1:tenant_b32,2:enterpriseRoot_b32}` | None; requires context | **Yes** | Empty | Yes |
| 0x70 | UploadBegin | `{1:slot,2:kind,3:ticket_bstr}` | SIGN | No | Empty | No |
| 0x71 | UploadChunk | `{1:offset,2:bytes_bstr}` | SIGN | No | Empty | No |
| 0x72 | UploadEnd | `{}` | SIGN | **Yes** | Signed | No |

GetInfo and Reset carry no parameter map, as in CTAP. The VCAP-wrapped forms of 0x01 and 0x02 exist only on an authenticator that implements the WebAuthn route (§7.14).

Commands that require a token permission append two keys after the business parameters: `254` = **pinUvAuthProtocol** (fixed at 2) and `255` = **pinUvAuthParam** (32 bytes, §8.1). Parameters below are written as `254:2, 255:pinUvAuthParam_b32`.

VCAP permission bits: `READ=0x0100`, `SIGN=0x0200`, `MANAGE=0x0400`. They lie above the CTAP permission bits (`0x01`–`0x80`), so a single permissions value can carry both. VCAP commands check only the VCAP bits.

### 7.0.1 Command Dispatch

For each completely reassembled request, the authenticator performs the following steps:

1. If a context exists on a transport other than the one carrying this request, and the command is not `GetInfo` or status-mode `GetState` (GetState with an empty parameter map, §7.4): if that context is held (§5.3), return `BUSY` without changing any state; otherwise zeroize it per §8.8 and continue.
2. If an upload is in progress and the command is not `GetInfo` / status-mode `GetState` / `Cancel` / `UploadChunk` / `UploadEnd`, return `BUSY`; the upload MUST NOT be zeroized.
3. If a context exists and its context or token deadline has passed (§8.1 step 4): when the command needs that context (it requires a token permission, or is UploadChunk / UploadEnd), return `PIN_TOKEN_EXPIRED` and zeroize the context; otherwise zeroize the context and continue.
4. Decode `command_u8`; an unknown command returns `INVALID_COMMAND`. Decode the parameters per §6.1.
5. If the command is `GetInfo`, execute §7.1. If the command is status-mode `GetState`, execute §7.4.1. If the command is `Cancel`, execute §7.3.
6. If the authenticator is in `RECOVERY_REQUIRED` and the command is not Reset, return `RECOVERY_REQUIRED`.
7. If the command is `ClientPIN`, execute §7.2. If the command is a standard CTAP operation, execute it per §7.14 when the request is VCAP-wrapped (§7.14.1), and otherwise as §7.13 specifies.
8. If the command requires a token permission, determine the required permission from the command table in §7.0 and execute §8.1. Otherwise (except Reset) a context is required; if absent, return `PUAT_REQUIRED`.
9. Execute the command.
10. After the command succeeds, confirm again that the deadlines and permissions are still valid (§8.1 steps 4 and 7); otherwise return the corresponding error.
11. If the transport was replaced during execution, zeroize the context and return `OPERATION_DENIED`.
12. If an error is returned, decide per §10.2 whether to zeroize the context.

### 7.1 GetInfo (0x04)

GetInfo is [CTAP authenticatorGetInfo][ctap-getinfo]. The request and the encoding of the response are as CTAP defines them, and the response is public, unsigned and changes no state. VCAP fixes the following member values; every other member is set as CTAP 2.3 defines it for the features the product implements, including `aaguid`, which identifies the product model:

| Key | Name | VCAP value |
|---:|---|---|
| 0x01 | versions | MUST contain `"VCAP_1_0"`, which announces this protocol; platforms detect VCAP support from it. MAY in addition contain `"FIDO_2_1"` and `"FIDO_2_3"`; no other value. For example `["FIDO_2_1", "FIDO_2_3", "VCAP_1_0"]` |
| 0x04 | options | `clientPin` as CTAP; `pinUvAuthToken`: true; `noMcGaPermissionsWithClientPin` absent, so browsers obtain `mc` / `ga` tokens with the PIN |
| 0x05 | maxMsgSize | 2048 |
| 0x06 | pinUvAuthProtocols | `[2]` |
| 0x08 | maxCredentialIdLength | At least 1023 (the largest VCAPREQ, §7.14.5) when the WebAuthn route is implemented; otherwise as the product supports |
| 0x09 | transports | Exactly the transports implemented: `"usb"` (CTAPHID, §11.2), `"nfc"` (§11.3), `"smart-card"` (CCID, §11.4) |
| 0x0A | algorithms | ES256 (-7) and EdDSA (-8) for standard operations; in addition `VCAP_ALG` (-65700) when the WebAuthn route is implemented (§7.14) |
| 0x0C | forcePINChange | Set by Personalize when the PIN is shorter than TrustConfig `minPinChars` (§7.11) |
| 0x0D | minPINLength | TrustConfig `minPinChars`; 4 before personalization |
| 0x18 | longTouchForReset | true: Reset requires a 5-second hold (§7.12) |

The VCAP lifecycle is reported by status-mode GetState (§7.4.1), not by GetInfo.

### 7.2 ClientPIN (0x06)

ClientPIN is [CTAP authenticatorClientPIN][ctap-clientpin] with [PIN/UV Auth Protocol Two][ctap-pinproto2] only. Its subcommands, parameters, responses, PIN encoding, PIN retry counter (8) and power-cycle lockout (3 consecutive failures) are as CTAP defines them. The authenticator supports the subcommands getPinRetries (0x01), getKeyAgreement (0x02), setPIN (0x03), changePIN (0x04), getPinToken (0x05) and getPinUvAuthTokenUsingPinWithPermissions (0x09); the others return `INVALID_SUBCOMMAND`, and `pinUvAuthProtocol ≠ 2` returns `INVALID_PARAMETER`.

VCAP adds the following rules:

1. **Context.** getKeyAgreement establishes the context of the transport that carries it (§5.3): it zeroizes any existing context of that transport, generates a new P-256 key agreement key pair, and derives `contextId` from it (§6.3). A PIN mismatch zeroizes the context, so the platform calls getKeyAgreement again.
2. **PIN policy.** The minimum PIN length is TrustConfig `minPinChars`, or 4 before personalization, counted in Unicode code points. Personalize sets forcePINChange when an existing PIN is shorter (§7.11); while it is set, getPinToken and getPinUvAuthTokenUsingPinWithPermissions return `PIN_POLICY_VIOLATION` and changePIN clears it.
3. **Permissions.** Besides the CTAP permissions, a token can carry the VCAP permissions `READ` (0x0100), `SIGN` (0x0200) and `MANAGE` (0x0400) (§7.0). VCAP permissions are not bound to an RP ID. Permissions are not accumulated: a new token replaces the previous one with exactly the requested permissions. A token from getPinToken carries only the CTAP permissions `mc` and `ga`, as CTAP defines for it, and never a VCAP permission, so it serves generic clients (§7.13, §7.14) but not VCAP commands, which require getPinUvAuthTokenUsingPinWithPermissions.
4. **Token lifetime.** The token's lifetime follows §5.3 (an initial usage time limit of 19 800 ms on every transport, then valid until the context ends). The token carries no user-presence state, so every UP-requiring command collects a new UP (§8.2).
5. **Lifecycle.** A successful setPIN in a personalized authenticator moves the lifecycle to PIN_READY (§5.1). In RECOVERY_REQUIRED every subcommand returns `RECOVERY_REQUIRED`.

### 7.3 Cancel (0x57)

**Parameters:** `{}`. **Result:** empty.

The authenticator performs the following steps:

1. If the parameters are not an empty map, return `INVALID_PARAMETER`.
2. If a held context exists on another transport, return `BUSY` (§7.0.1 step 1).
3. Zeroize the context of this transport per §8.8; the persistent KEL head and prepared key are kept.
4. Return `OK`.

Cancel requires neither a token nor UP. The platform determines the outcome of any earlier command per §12.3.

> Note: while waiting for UP, the authenticator is inside the current command (§8.2), so a Cancel command cannot arrive on the same transport during that time. Cancellation during the wait uses the transport: `CTAPHID_CANCEL` over USB HID (§11.2), removal from the field over NFC (§11.3), ICC power-off over CCID (§11.4), or a UP timeout.

### 7.4 GetState (0x50)

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

**Parameters:** `{1:challenge_b32, 254:2, 255:pinUvAuthParam_b32}`. **Required permission:** READ. **Result:** StateProof (§9.3).

The authenticator performs the following steps:

1. Authenticate per §8.1 (READ).
2. If not personalized, return `INVALID_STATE`.
3. Read the persistent state of the four slots; if the state of any slot is missing, corrupted, or not of the current reset epoch and configuration, return `RECOVERY_REQUIRED`.
4. Construct `authState` from the PIN record's `pinRetries`, the power-cycle lockout state, the current token permissions, the remaining initial-usage milliseconds (0 if already used) and the remaining context milliseconds.
5. Construct `stateBody` (§9.3).
6. Compute `signature = Ed25519(attestation key, "VCAP-STATE\0" ‖ stateBody)`.
7. Return `{1:stateBody_bstr, 2:signature}`.

A StateProof carries no lifecycle field: proof mode requires a PIN token, so the lifecycle is always PIN_READY. When the enterprise uses a StateProof as the basis for issuing a Ticket, the challenge MUST be generated by the enterprise and used only once.

### 7.5 CreateIdentity (0x51)

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

### 7.6 PrepareRotation (0x54)

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

### 7.7 Sign (0x53)

Generates a new signature over a message with a slot key. Larger messages use the upload form of §7.9; both forms have the same semantics.

**Parameters:**

| Key | Name | Type | Description |
|---:|---|---|---|
| 1 | slot | uint | 0..3 |
| 2 | kind | uint | 1..6, see below |
| 3 | ticket | bstr | Ticket envelope, ≤ 512 bytes (§9.2) |
| 4 | original | bstr | Message; complete request ≤ 2048 bytes |
| 254 | pinUvAuthProtocol | uint | 2 |
| 255 | pinUvAuthParam | b32 | §8.1 |

**kind:**

| kind | Name | Message type | Allowed owner | Message limit | KEL | Persistent write |
|---:|---|---|---|---:|---|---|
| 1 | ICP | KERI `icp` | CLIENT / WORK | 16384 | Yes | Slot latest, signature counter, lastSigned |
| 2 | IXN | KERI `ixn` | CLIENT / WORK | 16384 | Yes | Slot latest, signature counter, lastSigned |
| 3 | ROT | KERI `rot` | WORK | 16384 | Yes | Slot keys, latest, signature counter, lastSigned; prepared deleted |
| 4 | EXN | KERI `exn` | WORK | 16384 | No | Signature counter, lastSigned |
| 5 | RPY | KERI `rpy` | WORK | 16384 | No | Signature counter, lastSigned |
| 6 | AGENT | Agent session claims | CLIENT | 512 | No | Signature counter, lastSigned |

**Required permission:** SIGN. **UP:** yes, one new user action each time (sensor press, or NFC tap per §8.2). **Result:** Signed (§9.4).

The authenticator performs the following steps (**BEGIN phase**):

1. Authenticate per §8.1 (SIGN).
2. If `slot ∉ 0..3` or `kind ∉ 1..6`, return `INVALID_PARAMETER`.
3. If not personalized, return `INVALID_STATE`.
4. Read the slot's persistent state and verify its integrity (including keys and, where needed, prepared); on failure return `RECOVERY_REQUIRED`.
5. Verify the Ticket per §8.3, obtaining `originalLength`, `originalDigest` and `signCounter`.
6. If `kind` is not allowed for the slot's owner (column "Allowed owner" above), return `OPERATION_DENIED`. Pre-check persistent storage space per §8.7 (insufficient: `NO_SPACE`). If `kind` is a KEL kind (1..3), perform the key event pre-checks of §8.4.1. Otherwise, require the slot to be ACTIVE (else `INVALID_STATE`) and select the corresponding format check of §8.5.
7. Select the signing seed: old.next for ROT, current otherwise.
8. Prepare to sign with the selected key (§8.6).
9. Confirm again that the transport is still connected and no deadline has passed.

(**Data phase**)

10. Inline form: if `len(original) ≠ originalLength`, return `INVALID_LENGTH`. Upload form: received chunk by chunk per §7.9.2.
11. Process original: parse it per §8.4.2 or §8.5, compute `H(original)`, and include it in the signature computation (§8.6).

(**END phase**)

12. Confirm that the number of bytes received equals `originalLength`, otherwise `UPLOAD_INVALID`.
13. If `H(original) ≠ originalDigest`, return `TICKET_INVALID`.
14. Confirm that the context and token are still valid and the transport is unchanged.
15. KEL: complete the event checks of §8.4.2 (message fully parsed, fields and key bindings consistent); on failure return `INVALID_KERI_EVENT` or `KEY_BINDING`. Non-KEL: complete the format check of §8.5; on failure return `INVALID_KERI_EVENT`.
16. Collect one UP per §8.2 (hold 0).
17. After UP, check again: transport still connected (else `OPERATION_DENIED`), persistent storage space (else `NO_SPACE`), context and token deadlines (else `PIN_TOKEN_EXPIRED`), and that the slot's signature counter still equals `signCounter − 1` (else `TICKET_INVALID`). An expired deadline **MUST** cause rejection; deadlines are never extended for a signature.
18. Complete the 64-byte signature over original (§8.6); self-verify it with actualPublic; on failure return `INTERNAL`.
19. Commit atomically per §8.7: the signature counter becomes `signCounter`, `lastSigned` records this signature, and for KEL kinds the slot's latest (and keys, for ROT) advance.
20. Return Signed: `{1:signature, 2:actualPublic, 3:originalDigest, 4:originalLength, 5:signCounter}`.

Any failed step zeroizes the signing state, the parser and the whole context; when step 16 returns USER_ACTION_TIMEOUT, only the signing state, parser and upload state are cleared and the context and token are kept (§10.2). The signature MUST NOT leave the authenticator in any form before step 19 completes.

### 7.8 Recover (0x56)

Retrieves a stored **original signature** of the slot: that of the current latest key event, or that of the most recent signature of any kind (`lastSigned`). Earlier signatures are obtained from the enterprise archive.

**Parameters:** `{1:slot, 2:originalDigest_b32, 254:2, 255:pinUvAuthParam_b32}`. **Required permission:** READ. **UP:** no. **Ticket:** none. **Result:** Signed (original signature).

The authenticator performs the following steps:

1. Authenticate per §8.1 (READ).
2. If slot is out of range, return `INVALID_PARAMETER`.
3. Read the slot's persistent state; if corrupted, return `RECOVERY_REQUIRED`; if not ACTIVE, return `NOT_FOUND`.
4. If `originalDigest = lastSigned.originalDigest`, select lastSigned; otherwise, if `originalDigest = latest.originalDigest`, select latest; otherwise return `NOT_FOUND`.
5. Confirm that the context and token are still valid and the transport is still connected.
6. Return `{1:selected.originalSignature, 2:selected.actualPublic, 3:selected.originalDigest, 4:selected.originalLength, 5:selected.signCounter}`.

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
4. Process bytes as in §7.7 step 11; an error detected immediately by the parser returns `INVALID_KERI_EVENT`.
5. received += len(bytes).
6. Return empty success.

Out-of-order chunks, overruns, authentication failures and any other failure zeroize the upload and the whole context; the platform MUST NOT automatically resend the same UploadChunk.

#### 7.9.3 UploadEnd (0x72)

**Parameters:** `{254:2, 255:pinUvAuthParam_b32}` (no business parameters). **Required permission:** SIGN. **Result:** Signed.

The authenticator performs the following steps:

1. As §7.9.2 steps 1–2.
2. Execute §7.7 steps 12–20.
3. Clear the upload state.

### 7.10 BindEnterprise (0x63)

Binds a factory-state device to an enterprise tenant and enterprise root key. The first binding fixes the enterprise root key permanently; the enterprise performs it during enrollment per §12.5.

**Parameters:** `{1:tenant_b32, 2:enterpriseRoot_b32}`; no token authentication. **UP:** yes. **Result:** empty; the context is closed on success.

The authenticator performs the following steps:

1. Require a current context established by getKeyAgreement, otherwise `PUAT_REQUIRED`.
2. Validate the parameter key set and lengths.
3. If the lifecycle is not STOCK_UNBOUND, return `INVALID_STATE`.
4. If enterpriseRoot is not a safe public key (§3.1) or equals the attestation public key, return `INVALID_PARAMETER`.
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
3. Decode the envelope per §9.1; verify `"VCAP-TRUST\0" ‖ body` with the enterpriseRoot in the binding record; on failure return `CONFIG_INVALID`.
4. Validate body: version 2; device, tenant and resetEpoch match this device; ownerMask, minPinChars, roles and webauthnRpIds valid per §9.1 (keyIds in increasing byte order, public keys distinct from each other and from the enterprise root key and attestation key, safe public keys, capability bits only in the valid combinations of Appendix B). A device, tenant or resetEpoch mismatch returns `CONFIG_INVALID`; any other violation returns `INVALID_PARAMETER`.
5. Pre-check persistent storage space; if insufficient, return `NO_SPACE`.
6. Collect one UP per §8.2.
7. Confirm that the context is still valid and the transport is still connected.
8. Atomically commit: personalized=1 in the binding record, TrustConfig, four UNUSED slots, and forcePINChange if a PIN is set and its stored code-point length is below `minPinChars`.
9. After the write completes, zeroize the context and return empty success.

A configuration is installed once per reset epoch; changing role keys or configuration requires a full Reset. An existing PIN and existing FIDO credentials are kept; the lifecycle becomes PIN_READY if a PIN is set and PERSONALIZED_NO_PIN otherwise.

### 7.12 Reset (0x07)

Makes employee secrets unrecoverable and enters a new reset epoch.

**Parameters:** none (command byte only, as in CTAP); no token authentication and no context required. **UP:** yes, a **5-second hold**. **Result:** empty.

Reset has the code, power-up window and UP requirement of [CTAP authenticatorReset][ctap-reset]. It differs in that the enterprise binding and attestation identity are kept (§7.12.3) and the touch is held for 5 seconds.

#### 7.12.1 Authenticator Processing Steps

1. If the request carries any byte after the command byte, return `INVALID_LENGTH`.
2. If more than 10 000 ms have passed since this power-up, return `NOT_ALLOWED`. Power-up is the moment the authenticator is powered: USB attachment, or entry into an NFC field. A CCID ICC power-on is not a power-up.
3. Reset is available in every lifecycle state. In RECOVERY_REQUIRED, if the binding record (tenant, enterpriseRoot, resetEpoch) or the attestation identity cannot be read and verified, return `RECOVERY_REQUIRED`: Reset cannot keep a binding it cannot read, and MUST NOT return the authenticator to STOCK_UNBOUND.
4. Determine the set of secrets to destroy: always the PIN record, all private keys of the four slots including pre-rotation historical keys, `handleKey` (§7.14.3), and all FIDO credentials (§7.13).
5. Collect one UP per §8.2 with **hold = 5000 ms**; on timeout return `USER_ACTION_TIMEOUT`.
6. Confirm that the transport is still connected (else `OPERATION_DENIED`).
7. Durably write the reset intent record: the record to be written in step 10 and its digest. **From this step on, the Reset runs to completion and cannot be withdrawn.**
8. Make all secrets from step 4 unrecoverable, such that an attacker able to read the raw storage medium cannot reconstruct them; logical deletion, unlink or file system garbage collection does not satisfy this requirement. The authenticator MUST confirm that this step has completed before continuing.
9. Delete the PIN record, all state of the four slots, all FIDO credentials, and TrustConfig. In RECOVERY_REQUIRED this covers every storage area holding these objects, including data that could not be parsed.
10. If bound to an enterprise, atomically commit resetEpoch+1 and personalized=0, retaining the attestation identity, tenant and enterpriseRoot. In STOCK_UNBOUND, only the attestation identity remains.
11. Clear the reset intent record.
12. Zeroize any existing context and return empty success.

#### 7.12.2 Failure Semantics

- Any failure before step 7: no persistent change.
- Any failure or power loss after step 7: the Reset is completed at the next boot (§7.12.4).

#### 7.12.3 Scope of Reset

- Deactivating old AIDs on the network is the enterprise's responsibility (§12.7).
- Reset applies to all slots and all FIDO credentials together.
- From RECOVERY_REQUIRED, a successful Reset leaves the authenticator in ENTERPRISE_BOUND with resetEpoch+1, like any other Reset; the unreadable data is destroyed rather than retained.
- After Reset a bound authenticator is in ENTERPRISE_BOUND, and the new reset epoch requires Personalize only, with the existing binding; an unbound authenticator stays in STOCK_UNBOUND.

#### 7.12.4 Completing Reset at Boot

At every boot, before reading other persistent state, the authenticator checks for a reset intent record:

1. If no reset intent record exists, boot normally.
2. If the reset intent record is complete and its digest is correct, execute §7.12.1 steps 8–11 and then boot normally. Steps 8–10 are idempotent.
3. If the reset intent record is incomplete or its digest does not match, clear the record and boot normally. In this case either the write of step 7 did not complete (persistent state is the pre-Reset state) or the clearing of step 11 did not complete (persistent state is the post-Reset state).

Completing Reset at boot requires neither UP nor a context.

### 7.13 Standard CTAP Operations

The authenticator is also a FIDO2 authenticator. It implements [authenticatorMakeCredential][ctap-mc] (0x01), [authenticatorGetAssertion][ctap-ga] (0x02), [authenticatorGetNextAssertion][ctap-gna] (0x08) and [authenticatorSelection][ctap-selection] (0x0B) as CTAP 2.3 defines them, together with GetInfo, ClientPIN and Reset above. It MAY implement further CTAP commands, such as authenticatorCredentialManagement (0x0A), as CTAP defines them.

These operations follow CTAP, with the following VCAP rules:

1. **Separate key material.** FIDO credentials are generated and stored separately from the four KERI slots. A FIDO credential key MUST NOT sign through a VCAP operation. A slot key MUST sign only KERI messages and agent claims through the VCAP operations (§7.7, §7.14), and MUST NOT sign authenticator data or client data.
2. **Lifecycle.** Standard operations are available in every lifecycle state, independent of enterprise binding and personalization. In RECOVERY_REQUIRED they return `RECOVERY_REQUIRED` (§5.1).
3. **PIN and tokens.** The employee's single PIN serves both. A token obtained for CTAP permissions (`mc`, `ga`, …) authenticates CTAP operations as CTAP defines; a context whose token carries only CTAP permissions is never held (§5.3).
4. **User presence.** UP is collected per §8.2, so an NFC tap counts as one UP and a sensor press is required otherwise.
5. **Attestation.** Attestation for FIDO credentials MUST NOT use the VCAP attestation key, which identifies a single device. It uses batch attestation shared by a large population of devices, or self attestation.
6. **Reset.** Reset (§7.12) erases all FIDO credentials together with the KERI slots.
7. **Credential IDs.** Credential IDs of FIDO credentials MUST NOT begin with `"VH1"` or `"VQ1"`, the prefixes of slot handles and VCAP requests (§7.14).
8. **Signature counters.** FIDO credentials use their own signature counter. A standard operation never changes a slot's `signCounter` (§5.2) or any other slot state, so WebAuthn sign-in does not affect the counters on which Tickets are based.

### 7.14 VCAP Operations over WebAuthn

This section defines an optional feature (§2.1). An authenticator MAY implement it; one that does not lists no `VCAP_ALG` in GetInfo and processes every authenticatorMakeCredential and authenticatorGetAssertion per §7.13. The route is provisional: it depends on browsers and platforms forwarding the private algorithm identifier, long credential IDs and an opaque signature unchanged, and its encoding may change in a later version.

A web page can invoke CreateIdentity, Sign, proof-mode GetState, PrepareRotation and Recover through the standard WebAuthn API, with no software on the platform other than the browser. The browser carries the request to the authenticator as an ordinary authenticatorMakeCredential or authenticatorGetAssertion. The authenticator recognizes a VCAP request by a private COSE algorithm identifier and by payloads placed in fields that clients forward unchanged, and returns the result in fields that clients return to the page unchanged.

Each wrapped operation applies the same checks and commits the same state as its native command. Only the authorization and the encoding differ.

#### 7.14.1 Recognizing a Wrapped Request

`VCAP_ALG = -65700` is a COSE algorithm identifier in the private-use range (below -65536). It is listed in GetInfo `algorithms` (§7.1).

A request is **VCAP-wrapped** when all of the following hold, and is otherwise processed as a standard operation per §7.13:

- The authenticator is personalized, and `SHA-256(rpId)` is listed in TrustConfig `webauthnRpIds` (§9.1).
- For authenticatorMakeCredential: `VCAP_ALG` is the first entry of `pubKeyCredParams` that the authenticator supports, and `user.id` begins with the ASCII bytes `"VC1"`.
- For authenticatorGetAssertion: `allowList` has exactly one entry, and its `id` begins with the ASCII bytes `"VQ1"`.

For an RP ID outside `webauthnRpIds`, the authenticator treats `VCAP_ALG` as unsupported and a `"VQ1"` ID as an unknown credential, exactly as a security key without VCAP would. Pages on other RP IDs therefore cannot detect or use the VCAP function.

#### 7.14.2 Authorization and User Presence

- A wrapped request **MUST** carry `pinUvAuthParam`, verified as CTAP specifies for the command, with a token holding the CTAP permission `mc` (for authenticatorMakeCredential) or `ga` (for authenticatorGetAssertion) and, where the token is bound to an RP ID, bound to this rpId. Otherwise the authenticator returns `PUAT_REQUIRED` or the corresponding CTAP error. The context and token deadlines of §8.1 step 4 apply.
- These CTAP permissions take the place of READ, SIGN and MANAGE on this route; the operation is limited to the slot named by the request.
- A wrapped request with a zero-length `pinUvAuthParam` (the probe some clients send to select an authenticator before collecting the PIN) returns `PIN_AUTH_INVALID` **immediately and without collecting UP**, after the checks of §7.14.1 and the lifecycle check below; it creates no context and changes no state. Clients treat this answer as the selection of the authenticator and go on to collect the PIN. This deliberately departs from the CTAP rule that the authenticator first waits for user presence: a wrapped request names an enrolled RP ID and a VCAP slot or algorithm, so only this authenticator can serve it, and the one UP of the operation is collected after the PIN authorization. The probe reveals nothing beyond the silent preflight of §7.14.5 step 2. Requests that are not VCAP-wrapped, and authenticatorSelection, follow CTAP unchanged.
- Every other wrapped request with `up` true collects one new UP per §8.2, regardless of any user-presence state carried by the token. Read-only operations (GetState, Recover) also collect UP on this route, because the client requires it.
- The lifecycle MUST be PIN_READY; otherwise the authenticator returns `INVALID_STATE`, or `RECOVERY_REQUIRED` in RECOVERY_REQUIRED (§5.1).
- In a StateProof produced on this route, `authState.permissions` reports the VCAP permissions the operation stands in for: READ|MANAGE for CreateIdentity, READ for GetState, READ|SIGN for PrepareRotation.

#### 7.14.3 Slot Handle

A slot handle names one slot of the current reset epoch:

```
slotHandle = "VH1" ‖ CBOR([resetEpoch, slot, owner]) ‖ tag
tag        = first 16 bytes of HMAC-SHA-256(handleKey, "VCAP-HANDLE\0" ‖ CBOR([resetEpoch, slot, owner]))
```

`handleKey` is a 32-byte secret generated inside the authenticator at Personalize and destroyed by Reset. A handle is valid when its tag verifies, its resetEpoch is the current one, and its owner equals the slot's stored owner. An invalid handle is treated as an unknown credential (`NO_CREDENTIALS`).

#### 7.14.4 CreateIdentity through authenticatorMakeCredential

**Request fields:**

| Field | Content |
|---|---|
| rp.id | An RP ID listed in `webauthnRpIds` |
| user.id | `"VC1" ‖ CBOR({1:slot, 2:owner})` (≤ 64 bytes) |
| clientDataHash | Used as the StateProof challenge |
| pubKeyCredParams | `[{type:"public-key", alg:-65700}]` |
| options | `rk` false or absent; an `rk` of true returns `UNSUPPORTED_OPTION` |
| excludeList | Entries that are slot handles are ignored |

The authenticator performs the following steps:

1. Verify the authorization per §7.14.2 (`mc`).
2. Execute §7.5 steps 2–7.
3. Collect one UP per §8.2.
4. Execute §7.5 step 8 (atomic commit); then generate a StateProof per §7.4.2 steps 3–7 with `challenge = clientDataHash`.
5. Return the authenticatorMakeCredential response with `fmt = "none"`, an empty `attStmt`, and authData with flags UP, UV and AT set, signCount 0, and attested credential data:
   - `credentialId` = the slot handle (§7.14.3);
   - `credentialPublicKey` = `{1:1, 3:-65700, -1:6, -2:currentPublic_b32, -70000:StateProof_bstr}` (an OKP Ed25519 key carrying the StateProof under a private label).

The enterprise verifies the clientDataJSON, the StateProof with the registered attestation key, and that the StateProof challenge equals `SHA-256(clientDataJSON)` (§12.9.1).

#### 7.14.5 Operations through authenticatorGetAssertion

**Request payload.** The single allowList entry carries the request:

```
VCAPREQ = "VQ1" ‖ CBOR(request)                    ; ≤ 1023 bytes
request = {1:op, 2:slotHandle, ? 3:kind, ? 4:ticket_bstr, ? 5:original_bstr, ? 6:originalDigest_b32}
```

| op | Operation | Further keys | Executes | Result |
|---:|---|---|---|---|
| 1 | Sign | 3, 4, 5 | §7.7 steps 2–20 | Signed |
| 2 | GetState (proof mode) | ? 6 | §7.4.2 steps 2–7, `challenge = clientDataHash`; with key 6, also the selection of §7.8 step 4 | StateProof; with key 6, `[StateProof_bstr, Signed / null]` |
| 3 | PrepareRotation | none | §7.6 steps 2–8, `challenge = clientDataHash` | StateProof |
| 4 | Recover | 6 | §7.8 steps 2–6 | Signed |

With key 6, op 2 resolves an unknown outcome in one call (§12.9.3). `Signed` is the record that §7.8 step 4 selects for `originalDigest`, encoded as in §7.8 step 6, or null when the slot is not ACTIVE or neither lastSigned nor latest matches. The operation remains read-only: it signs nothing and writes no state.

The slot is the one named by `slotHandle`. The largest message on this route is therefore `1023 − 3 − len(CBOR(request))` with `original` counted as an empty bstr; with a typical Ticket of about 180 bytes this leaves roughly 780 bytes. A message that does not fit in VCAPREQ is signed through the native route with the upload commands (§7.7, §7.9).

The authenticator performs the following steps:

1. Decode VCAPREQ per §6.1 and verify the slot handle per §7.14.3. A malformed VCAPREQ or invalid handle is treated as an unknown credential (`NO_CREDENTIALS`).
2. If `up` is false (a silent preflight by the client), return the response of step 5 with UP clear in the flags and a zero-length `signature`, without authorization, signing or any change of state.
3. Verify the authorization per §7.14.2 (`ga`).
4. Execute the operation as the table specifies. For op 1, step 16 of §7.7 collects the UP. For ops 2–4, the authenticator collects one UP per §8.2 after the checks of the underlying procedure and before any write or result.
5. Return the authenticatorGetAssertion response:
   - `credential` = `{type:"public-key", id:VCAPREQ}`;
   - `authData` = `rpIdHash ‖ flags ‖ signCount`, with UP and UV set and `signCount` = the slot's signature counter after the operation (§5.2);
   - `signature` = `CBOR([result_bstr, deviceSig_b64])`, where `result_bstr` is the CBOR encoding of the result and
     `deviceSig = Ed25519(attestation key, "VCAP-WEBAUTHN\0" ‖ authData ‖ clientDataHash ‖ H(result_bstr))`;
   - `user` and `numberOfCredentials` are omitted.

`deviceSig` binds the result to this device, the RP ID and the page's clientData, which carries the enterprise challenge and the origin. The KERI signature is inside `result_bstr`; slot keys never sign `authData` or `clientDataHash`.

Errors are the status codes of Section 10. Browsers report them to the page as a generic failure, so the page determines the outcome from the slot's signature counter (§12.9.3).


---

## 8. Common Authenticator Procedures

### 8.1 Verifying Command Authentication

Applies to every command carrying pinUvAuthProtocol (254) and pinUvAuthParam (255). Inputs: `command_u8`, the complete parameter map `P_full`, and the required permission `required`.

```
P    = the original deterministic CBOR map P_full without keys 254 and 255
msg  = "VCAP-CMD\0" ‖ contextId ‖ command_u8 ‖ H(CBOR(P))
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

- Binding each command to contextId and the token confines it to its context: an authenticated command cannot be replayed into another context. There is no sequence number or replay cache; within one context, single use of Tickets comes from the signature counter (§8.3) and freshness of StateProofs from their challenges.
- Each UploadChunk is authenticated independently, so authentication covers its offset and bytes.
- Successful authentication shows only that the request comes from the platform holding the token; Ticket, UP and commit eligibility are checked separately.

### 8.2 Collecting User Presence (UP)

Inputs: `hold_ms` (0 for ordinary operations, 5000 for Reset), the current transport, and `deadline` (the result of §8.1 step 8; Reset has no context and no deadline).

The authenticator performs the following steps:

1. If the transport is NFC, `hold_ms` is 0, and the tap of the current field session has not been consumed (§11.3), mark it consumed and return success. Over USB HID and CCID there is no tap; UP always comes from the sensor.
2. Turn on the presence indicator; turn it off however this procedure ends. The authenticator MUST have a touch sensor and a visible presence indicator light that is lit only while it waits for UP.
3. Record the start time `t0`. Let `hold = max(hold_ms, 30)`.
4. Loop until a result is reached:
   1. If the transport has been disconnected, return `OPERATION_DENIED`.
   2. If the transport reports a cancellation (`CTAPHID_CANCEL`, §11.2), return `KEEPALIVE_CANCEL`.
   3. If a `deadline` is set and has passed, return `PIN_TOKEN_EXPIRED`.
   4. If `now − t0 ≥ 30 000 ms`, stop waiting and return `USER_ACTION_TIMEOUT`.
   5. Release detection: a touch already held when the request starts does not count; the sensor MUST first be released and stay released for at least 30 ms.
   6. Press detection: a subsequent new press held for at least `hold` is accepted; a release before then returns to waiting for a press.
5. On acceptance, return success.

Rules:

- Each UP-requiring request consumes its own new sensor press or its own NFC tap. Over NFC one tap satisfies at most one request; a further UP-requiring request in the same field session needs a sensor press or a new tap. The authenticator MUST NOT latch or reuse a press or tap, and a platform MUST NOT retry a signature automatically.
- Reset (`hold_ms` = 5000) always requires the sensor to be held; an NFC tap never satisfies it.
- While waiting, the authenticator stays in the current command and reports progress as the transport defines (CTAPHID keepalive, §11.2; status polling over NFC, §11.3, and CCID, §11.4).
- The effective wait window is min(30 s, remaining context time). Sign / UploadEnd is itself a use of the token, so the UP wait is unaffected by the initial usage time limit. If the user does not touch within 30 s, `USER_ACTION_TIMEOUT` is returned and the token remains valid; the platform MAY start the signature again without asking for the PIN again.
- UP establishes that someone present approved one operation; review of the message content takes place off-device (§13.2). An NFC tap is a weaker signal than a sensor press, since it can also come from leaving the authenticator on the reader.

### 8.3 Verifying a Ticket

Inputs: `ticket_bstr`, the request `kind`, the slot's persistent state, and TrustConfig.

The authenticator performs the following steps:

1. If `len(ticket) > 512`, return `INVALID_LENGTH`.
2. Decode `[body_bstr, keyId_tstr, signature_b64]` per §6.1.
3. Look up keyId in TrustConfig `roles`; if not found, return `TICKET_INVALID`.
4. Verify `"VCAP-SIGN\0" ‖ body_bstr` with that role public key; on failure return `TICKET_INVALID`.
5. Decode `body = [2, kind, signerKeyRef_b32, signCounter, originalDigest_b32, originalLength]`; if the version is not 2, return `INVALID_PARAMETER`.
6. If `body.kind ≠ request kind`, return `TICKET_INVALID`.
7. Let owner be the slot's owner; if the role's `capabilityMask` does not contain `bit(8·(owner−1) + (kind−1))`, return `TICKET_INVALID` (valid combinations in Appendix B).
8. If `signCounter ≠ the slot's signature counter + 1` (with overflow check), return `TICKET_INVALID`.
9. Compute KeyRef per §6.3 using the **actual signing public key** (old.next for ROT, current otherwise); if `signerKeyRef ≠ KeyRef`, return `TICKET_INVALID`.
10. If `originalLength ∉ 1..limit(kind)`, return `INVALID_LENGTH`.
11. Store the Ticket and its verification result.

The Ticket binds the remaining facts indirectly. KeyRef binds the device, reset epoch, slot, owner and actual signing key. The signature counter binds the Ticket to exactly one signature of that slot. The message digest, the length and the parser bind the AID, seq, said and prior.

The authenticator keeps no record of used Tickets: the signature counter makes every Ticket single-use, since a committed signature advances the counter and invalidates every Ticket issued for the same or an earlier value. A Ticket is independent of the context, so it remains usable across disconnection, PIN errors and new contexts until the slot's next signature. It carries no time limit (§13.2).

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

1. The message is one complete JSON object within the length limit that satisfies the event syntax of §8.4.3, with no duplicate top-level keys and no trailing bytes.
2. The size field of the version string `v` equals the total message length.
3. `t` equals the event type for the kind (`icp` / `ixn` / `rot`).
4. `d`, `i` and `p` (IXN / ROT) are 44 bytes with an `E` prefix and satisfy the expected values of §8.4.1.
5. `s` equals the expected sequence number.
6. ICP / ROT: `k` has exactly 1 entry, equal to `qb64("D", signing public key)`; `kt="1"`; `n` has exactly 1 entry, equal to `commit(next key)` (next for ICP, newNext for ROT) per §6.2; `nt="1"`.
7. Delegated event types (`dip` / `drt`) are rejected.

A format or field mismatch returns `INVALID_KERI_EVENT`; a key, commitment or AID mismatch returns `KEY_BINDING`.

SAID computation, witnesses, delegation and network acceptance are verified in full by the enterprise (§12.8).

#### 8.4.3 KERI Event Syntax

The authenticator accepts KERI 1.0 events in JSON serialization with the following syntax, and rejects any other message with `INVALID_KERI_EVENT`. Platforms MUST produce events in this form.

1. The message is valid UTF-8 and a JSON text per RFC 8259 with no insignificant whitespace: no space, tab, line feed or carriage return outside string values.
2. The top-level object has exactly the following fields, in this order:

   | Event | Fields |
   |---|---|
   | `icp` | `v`, `t`, `d`, `i`, `s`, `kt`, `k`, `nt`, `n`, `bt`, `b`, `c`, `a` |
   | `ixn` | `v`, `t`, `d`, `i`, `s`, `p`, `a` |
   | `rot` | `v`, `t`, `d`, `i`, `s`, `p`, `kt`, `k`, `nt`, `n`, `bt`, `br`, `ba`, `a` |
   | `exn` | `v`, `t`, `d`, `i` first, in this order; further fields as KERI defines |
   | `rpy` | `v`, `t`, `d` first, in this order; further fields as KERI defines |

3. `v` is exactly `"KERI10JSON"` followed by six lowercase hexadecimal digits and `"_"`; the digits give the total message length in bytes.
4. `s` and `bt` are lowercase hexadecimal strings without leading zeros (`"0"` for zero); `s` has at most 16 digits.
5. The string values of `v`, `t`, `d`, `i`, `s`, `p`, `kt`, `nt` and the entries of `k` and `n` contain no backslash escape.
6. The values of `b`, `c`, `a`, `br`, `ba` and the further fields of `exn` and `rpy` follow the JSON grammar of RFC 8259. The authenticator checks only that grammar; uniqueness of keys inside these values is checked by the enterprise (§12.8 item 3).

### 8.5 Non-KEL Format Checks

All non-KEL signatures use the current key of an ACTIVE slot. Their commit writes only the slot's signature counter and lastSigned (§8.7).

#### 8.5.1 EXN (kind 4, WORK)

Complete JSON; total length matches `v`; `t="exn"`; `i` equals this slot's AID. Route, recipients, attachments and business meaning are verified by the enterprise.

#### 8.5.2 RPY (kind 5, WORK)

Complete JSON; total length matches `v`; `t="rpy"`. Route, identity and business meaning are verified by the enterprise.

#### 8.5.3 AGENT (kind 6, CLIENT)

```
original = "VCAP-AGENT-SESSION\0" ‖ 0x06 ‖ aid_t44 ‖ body
body     = CBOR([1, receiver_tstr, nonce_b32, issued, expires, claims_bstr])
claims   = CBOR({1:walletProfile_tstr})
```

| Field | Content |
|---|---|
| `0x06` | The AGENT kind value |
| `aid_t44` | The slot's AID as 44 bytes of qb64 text |
| `receiver` | The receiver identifier the enterprise assigned for the AGENT purpose (VCAP-EI §7.5) |
| `nonce` | 32 random bytes generated by the platform |
| `issued`, `expires` | uint, seconds since 1970-01-01T00:00:00Z |
| `walletProfile` | The name of a wallet operation profile (VCAP-EI Appendix C) |

The authenticator checks: the domain separation tag, the kind byte, that `aid_t44` equals this slot's AID, that the total length is ≤ 512 and equals the Ticket's originalLength, and the Ticket digest. The body is opaque to the authenticator; the enterprise verifies claims, receiver, nonce and `0 < expires − issued ≤ 300`.

The Agent requests a session permits are exactly those of the wallet operation profile named in `claims`. An enterprise service MUST NOT accept an AGENT session for KEL events, RPY or EXN, for Agent creation, or for administration.

### 8.6 Signature Computation

The signature is a 64-byte Ed25519 signature over the message, verifiable under RFC 8032 (§6.4) with `actualPublic`. Any computation with the following properties conforms, including the choice of nonce generation and the processing of a message received in several chunks:

1. The authenticator MUST complete the signature only after UP (§7.7 step 18); before that, no signature or value from which one could be completed leaves the authenticator.
2. The authenticator MUST self-verify the signature with `actualPublic` before it is committed, and return `INTERNAL` on failure.
3. The authenticator MUST NOT write the message to persistent storage.

### 8.7 Atomic Commit

| Operation | Objects committed in one atomic commit |
|---|---|
| BindEnterprise | Binding record |
| Personalize | Binding record, TrustConfig, four UNUSED slots |
| CreateIdentity | The slot's keys and state |
| PrepareRotation | The slot's prepared entry (latest unchanged) |
| Sign ICP / IXN | The slot's latest (= this event, including the original signature), signature counter and lastSigned |
| Sign ROT | The slot's keys (current←old.next, next←newNext), latest, signature counter and lastSigned; prepared deleted |
| Sign EXN / RPY / AGENT | The slot's signature counter and lastSigned |
| Reset | Reset intent record → secret destruction → new reset epoch → reset intent record cleared (§7.12) |
| GetState, Recover | No business write |

Rules:

1. The written content is determined entirely inside the authenticator.
2. A signature or StateProof is returned only after the write completes.
3. After a ROT write, storage is in exactly one of two states: the pre-rotation keys, latest and prepared; or the post-rotation keys and latest (without prepared). Mixed intermediate states are impossible, and one rotation is applied at most once.
4. After a write error or an error response, the platform determines the outcome per §12.3.
5. Slot state stores latest's kind, seq, said, originalLength, originalDigest and original signature, and `lastSigned` (kind, signCounter, actualPublic, originalLength, originalDigest and signature of the most recent signature of any kind), for use by §7.8.
6. ROT is not required to destroy pre-rotation private keys; until Reset, an attacker able to read the raw storage medium may recover historical keys. Only Reset guarantees that they are unrecoverable (§13.1).

### 8.8 Zeroizing a Context

The authenticator performs the following steps:

1. Clear the fragment buffer and pending response.
2. Clear the upload, the signing state (including every intermediate value and key copy) and the parser.
3. Clear the token, permissions, key agreement private key, shared secret and contextId.
4. Release the context's binding to its transport.

The persistent KEL head and prepared key are kept.

---

## 9. Data Structures

The leading integer of the TrustConfig body, the Ticket body and stateBody is a structure version. Its value 2 is independent of the version of this document.

### 9.1 TrustConfig

```
envelope = [body_bstr, rootSignature_b64]                  ; ≤ 1536 bytes
           ; rootSignature = Ed25519(enterpriseRoot, "VCAP-TRUST\0" ‖ body)
body     = [2, device_b32, tenant_b32, resetEpoch,
            ownerMask, minPinChars, roles, webauthnRpIds]
role     = [keyId_tstr, capabilityMask, public_b32]
webauthnRpIds = [* rpIdHash_b32]
```

| Field | Constraint |
|---|---|
| ownerMask | Only bit0 (CLIENT) / bit1 (WORK); non-zero |
| minPinChars | 4..63 (an enterprise MAY choose 8 or more) |
| roles | 1..8 entries; keyId is 1..16 bytes of UTF-8, in strictly increasing byte order |
| role.public | Distinct from each other and from the enterprise root key and attestation key; safe public key (§3.1) |
| capabilityMask | Only the valid bits of Appendix B; non-zero |
| webauthnRpIds | 0..4 entries; each is SHA-256 of an enterprise RP ID; strictly increasing byte order. The RP IDs from which VCAP-wrapped operations are accepted (§7.14.1); an empty list disables the WebAuthn route |

### 9.2 Ticket

```
ticket = [body_bstr, keyId_tstr, signature_b64]            ; ≤ 512 bytes
         ; signature = Ed25519(role.public, "VCAP-SIGN\0" ‖ body)
body   = [2, kind, signerKeyRef_b32, signCounter,
          originalDigest_b32, originalLength]
```

| Field | Description |
|---|---|
| kind | 1..6 |
| signerKeyRef | §6.3, computed over the actual signing public key |
| signCounter | The slot's signature counter value after this signature, i.e. the current value + 1 |
| originalDigest | H(message) |
| originalLength | 1..limit(kind) |

The enterprise learns the slot's current signature counter from the last archived Signed (§9.4), from a StateProof (§9.3), or from the `signCount` of a WebAuthn response (§7.14). For several consecutive signatures on one slot it issues Tickets with consecutive counter values; each becomes usable once the previous one has been used.

### 9.3 StateProof

```
StateProof = {1:stateBody_bstr, 2:signature_b64}
             ; signature = Ed25519(attestation key, "VCAP-STATE\0" ‖ stateBody)
stateBody  = [2, device_b32, resetEpoch, configurationDigest_b32,
              challenge_b32, authState, slots]                         ; ≤ 1536 bytes
authState  = [pinRetries, powerCycleState(0/1), permissions, initialUsageRemainingMs, contextRemainingMs]
slots      = [slot0, slot1, slot2, slot3]
slot       = [index, owner, phase, currentPublic_b32/null, nextPublic_b32/null,
              preparedPublic_b32/null, aid_t44/null, head/null, signCounter]
head       = [kind, seq, said_t44, originalLength, originalDigest_b32]
```

- All four slots are returned together in every StateProof.
- `preparedPublic` is the actual newNext; the existing next key signs the rot.
- `head.kind` is ICP, IXN or ROT and matches the owner. The original signature is retrieved with Recover.
- The platform computes KeyRef itself per §6.3.
- Verifiers verify a StateProof with the device's attestation public key registered at onboarding (§12.5 step 2).

### 9.4 Signed

```
Signed = {1:signature_b64, 2:actualPublic_b32, 3:originalDigest_b32, 4:originalLength, 5:signCounter}
```

Sign, UploadEnd and Recover use this same structure; `signCounter` is the slot's counter value assigned to this signature. The CESR index is always 0 and is encoded by the platform. The platform MUST verify the signature independently against its own copy of the message and the expected public key.

---

## 10. Status Codes

### 10.1 Status Code Table

Status codes are the [CTAP status codes][ctap-errors] plus the VCAP codes 0xF0–0xF7. ClientPIN (§7.2) and the standard CTAP operations (§7.13) return status codes as CTAP defines them. The table lists the codes that VCAP commands and VCAP-wrapped operations (§7.14) return, with the platform action for each; VCAP commands MUST NOT return other codes. A platform receiving an unlisted code SHOULD report a protocol error and MUST NOT interpret it as a PIN error or as safe to retry. An error response is a single status byte with no map.

| Code | Name | Meaning | Platform action |
|---|---|---|---|
| 0x00 | OK | Success | If a result is present, verify its structure and signature / proof |
| 0x01 | INVALID_COMMAND | Unknown command | Fix the implementation |
| 0x02 | INVALID_PARAMETER | Missing / extra keys, invalid combination, wrong fixed protocol number | Fix the request |
| 0x03 | INVALID_LENGTH | Length or integer out of range | Fix the request |
| 0x06 | BUSY | Another transport holds a held context, or an upload is in progress (CTAP1_ERR_CHANNEL_BUSY). Returned as the status byte of the VCAP response (§11.1), on every transport | Wait and retry; any existing upload continues |
| 0x12 | INVALID_CBOR | Encoding, type, ordering, depth or trailing-byte violation | Fix the encoding |
| 0x27 | OPERATION_DENIED | Owner or permission denied; disconnection during UP; transport replaced during execution | Report as distinct from a PIN error; obtain the user's consent again |
| 0x28 | NO_SPACE | Insufficient persistent storage | Maintenance |
| 0x2b | UNSUPPORTED_OPTION | VCAP-wrapped MakeCredential with `rk` true (§7.14.4) | Fix the request |
| 0x2d | KEEPALIVE_CANCEL | UP wait cancelled by `CTAPHID_CANCEL` | Do not re-sign automatically; reconcile per §12.3 if needed |
| 0x2e | NO_CREDENTIALS | VCAP-wrapped request with an invalid slot handle or VCAPREQ (§7.14) | Obtain a current slot handle |
| 0x2f | USER_ACTION_TIMEOUT | UP wait timed out after 30 s (PIN_TOKEN_EXPIRED if the context deadline comes first) | Do not re-sign automatically |
| 0x30 | NOT_ALLOWED | Reset sent more than 10 s after power-up | Ask the user to reinsert or re-tap the authenticator and retry immediately |
| 0x33 | PIN_AUTH_INVALID | Command authentication with the token failed (§8.1) | Call getKeyAgreement again and obtain a token |
| 0x36 | PUAT_REQUIRED | Missing context, token or authentication fields | Call getKeyAgreement / obtain a token first |
| 0x38 | PIN_TOKEN_EXPIRED | Token or context deadline passed | Authorize again |
| 0x7f | INTERNAL | RNG, cryptographic engine or invariant failure | Stop and report |
| 0xf0 | INVALID_STATE | Lifecycle, slot or operation conditions not met | Query actual state with GetState |
| 0xf1 | CONFIG_INVALID | TrustConfig signature, device, tenant or reset epoch mismatch (§7.11) | Check the TrustConfig issued for this device and reset epoch |
| 0xf2 | NOT_FOUND | The slot has no latest event, or required data does not exist | Query actual state |
| 0xf3 | INVALID_KERI_EVENT | Message parsing or local KEL rules not satisfied | Check the message; for a KEL signature the head may be outdated: establish a new context, GetState, then request a new Ticket |
| 0xf4 | KEY_BINDING | Actual key, pre-rotation commitment or AID mismatch | Check the message; establish a new context, check the keys with GetState, then request a new Ticket |
| 0xf5 | TICKET_INVALID | Ticket signature / binding / signature counter mismatch | Request a new Ticket, or query actual state |
| 0xf6 | RECOVERY_REQUIRED | Storage contains unrecognized or corrupted data | Reset (§7.12); offline maintenance if Reset also returns RECOVERY_REQUIRED |
| 0xf7 | UPLOAD_INVALID | Upload progress, final length / digest or phase error | Start over (new context) |

Codes below 0xF0 are CTAP status codes with their CTAP meaning (BUSY is CTAP1_ERR_CHANNEL_BUSY, NO_SPACE is CTAP2_ERR_KEY_STORE_FULL and INTERNAL is CTAP1_ERR_OTHER). Codes 0xF0–0xF7 are VCAP-specific codes in the CTAP vendor range.

### 10.2 Context Zeroization on Error

Except for `BUSY` and the `USER_ACTION_TIMEOUT` of Sign / UploadEnd described below, an error MUST zeroize the whole context (§8.8) when any of the following holds:

1. An upload is in progress when the error occurs; or
2. The command is one of CreateIdentity, Sign, PrepareRotation, Personalize, BindEnterprise, Reset, UploadBegin / Chunk / End; or
3. The status code is one of PIN_AUTH_INVALID, PIN_TOKEN_EXPIRED, INTERNAL, RECOVERY_REQUIRED, TICKET_INVALID, CONFIG_INVALID, KEEPALIVE_CANCEL.

When Sign or UploadEnd returns USER_ACTION_TIMEOUT, the authenticator clears the signing state, parser and upload state and keeps the context and token (§8.2). Other errors (for example `INVALID_PARAMETER` from GetState) keep the context. `BUSY` always keeps the current upload and context.

### 10.3 Status Codes and Commitment

Status codes are unauthenticated. A platform determines whether a write occurred only per §12.3, and MUST NOT automatically retry a PIN or re-sign on the basis of a status code.

---

## 11. Transport Bindings

VCAP messages are carried over the CTAP transports, CTAPHID over USB HID (§11.2) and the CTAP NFC binding (§11.3), and over USB CCID (§11.4), which carries the APDUs of the CTAP NFC binding over a contact smart-card interface. The message encoding (§11.1) is identical on all of them. Each transport is an optional feature (§2.1); an authenticator implements at least one.

### 11.1 Message Encoding

```
request  = command_u8 ‖ CBOR(parameters_map)
response = status_u8 [‖ CBOR(result)]     ; result appended only when status=OK and a result exists
```

- A complete request and a complete response are each ≤ 2048 bytes.
- The message of a Sign request (≤ 16 384 bytes) is carried inline when the complete request is ≤ 2048 bytes, and otherwise through the upload commands of §7.9.
- A transport carries one request at a time. A new request arriving before the previous one completes is rejected by the transport (§11.2, §11.3) and is not executed.
- A transport-level success reports delivery only. The business result is carried in `status_u8` (Section 10), and commitment is established per §12.3.

**Lost responses.** When a response is lost on any transport, the platform **MUST NOT** automatically resend the whole command. It recovers per §12.3:

- KEL signature: new context → fresh GetState → Recover if needed.
- CreateIdentity / PrepareRotation: read the actual authenticator state with GetState and reconcile.
- PIN operations: query getPinRetries, then the user repeats the operation.
- Non-KEL signature: GetState shows whether the slot's counter reached the Ticket's `signCounter`; if it did, Recover returns the signature while no later signature exists.

### 11.2 USB HID: CTAPHID

VCAP uses the [CTAPHID binding of CTAP 2.3][ctap-usb] unchanged; a VCAP request and response (§11.1) are the payload of `CTAPHID_CBOR`. The following rules relate it to VCAP:

- One CTAPHID channel (CID) is one transport in the sense of §3.1; a context belongs to the CID on which getKeyAgreement was sent. A `CTAPHID_INIT` on that CID, or USB detachment, zeroizes the context.
- Once a transaction on another CID has ended, a request from that CID while a held context exists receives a `CTAPHID_CBOR` response whose status byte is `BUSY` (§7.0.1 step 1); a context that is not held is zeroized and the request proceeds (§5.3). A request arriving on any CID while a transaction is in progress receives the CTAPHID-level `ERR_CHANNEL_BUSY` as CTAPHID defines.
- While waiting for UP the authenticator sends `CTAPHID_KEEPALIVE` with `STATUS_UPNEEDED`. `CTAPHID_CANCEL` ends the wait: the command returns `KEEPALIVE_CANCEL` (§8.2) and the context is zeroized (§10.2).

### 11.3 NFC

VCAP uses the [NFC binding of CTAP 2.3][ctap-nfc] unchanged, including the FIDO AID, command chaining, `GET RESPONSE` and status polling with [`NFCCTAP_GETRESPONSE`][ctap-nfc-getresponse]. The authenticator reassembles requests of at most 2048 bytes (§11.1). The following rules relate it to VCAP:

- **Field session.** A field session begins when the authenticator is powered by the reader's field and ends when it leaves the field. The field session is one transport. `SELECT` of the FIDO AID and leaving the field both zeroize the context.
- **Tap as UP.** Entering the field counts as one user action. The first UP-requiring request in the field session consumes it (§8.2 step 1); later UP-requiring requests in the same session wait for a sensor press. Reset never accepts the tap.
- **Cancellation.** The platform cancels by ending the field session. A Cancel command (§7.3) between two commands remains available.
- **Leaving the field during a command.** The command ends with power loss and no signature leaves the authenticator. If it had already committed persistent state (§8.7), the platform recovers per §12.3 in a new field session; an interrupted Reset completes at the next power-up (§7.12.4).

### 11.4 USB CCID

A USB authenticator MAY present a USB CCID interface (USB-IF *Device Class Specification for USB Chip/Smart Card Interface Devices* 1.1, interface class `0x0B`) with one slot holding a permanently present ICC. The ICC carries the APDU layer of the [CTAP NFC binding][ctap-nfc] unchanged: `SELECT` of the FIDO AID, `NFCCTAP_MSG`, command chaining, `GET RESPONSE` and status polling with `NFCCTAP_GETRESPONSE`. A VCAP request and response (§11.1) are the payload of `NFCCTAP_MSG` exactly as over NFC, and the authenticator reassembles requests of at most 2048 bytes. Platforms reach this interface through the operating system's smart-card service (for example PC/SC).

The following rules relate it to VCAP:

- **Card session.** A card session begins with `PC_to_RDR_IccPowerOn` and ends with `PC_to_RDR_IccPowerOff`, USB reset or USB detachment. The card session is one transport. `SELECT` of the FIDO AID and the end of the card session both zeroize the context.
- **UP.** A card session provides no tap: every UP-requiring request waits for a sensor press (§8.2), and the authenticator reports `STATUS_UPNEEDED` in response to status polling while it waits.
- **Cancellation.** The platform cancels a UP wait by ending the card session. A Cancel command (§7.3) between two commands remains available.
- **Ending the card session during a command.** The command ends and no signature leaves the authenticator. If it had already committed persistent state (§8.7), the platform recovers per §12.3 in a new card session.
- **Reset window.** The 10-second window of §7.12.1 step 2 runs from USB attachment; an ICC power-on does not reopen it.
- **Coexistence.** An authenticator that presents both a CTAPHID interface and a CCID interface treats each CTAPHID channel and the card session as separate transports, and applies §5.3 between them.
- **ATR.** The answer-to-reset is product-defined; platforms identify the authenticator by a successful `SELECT` of the FIDO AID followed by GetInfo `versions` containing `"VCAP_1_0"`.

---

## 12. Platform and Enterprise Procedures

This section specifies the steps that platforms and enterprises **MUST** follow when using the authenticator. The security of the authenticator depends on them: for example, non-KEL signature results are held only by the platform Outbox and the enterprise archive, so a lost response is recovered from there.

### 12.1 Establishing a Context and Authorization

The platform performs the following steps:

1. Open the transport: allocate a CTAPHID channel (§11.2), or `SELECT` the FIDO AID over NFC (§11.3) or in a CCID card session (§11.4). Confirm that GetInfo `versions` contains `"VCAP_1_0"`.
2. Send ClientPIN getKeyAgreement to obtain the authenticator's keyAgreement; compute contextId per §6.3; generate a new ephemeral P-256 key as the platform keyAgreement for subsequent subcommands.
3. Ask the user for the PIN and request, in one call, all permissions the operation needs (for example `READ|SIGN` for signing) with getPinUvAuthTokenUsingPinWithPermissions.
4. Decrypt pinUvAuthToken to obtain the token. The PIN, pinHash, shared secret and token MUST NOT be logged; the PIN entered by the user MUST be cleared on completion, cancellation, backgrounding or unload.
5. When token permissions, device identity or slot state need confirmation, check `authState.permissions` and slot state with GetState (with a challenge); for a normal signature, decide per §12.2 step 0.
6. Reuse a valid token for subsequent commands; ask for the PIN again only after expiry, disconnection, permission escalation or revocation. A platform MUST NOT keep the token alive with idle background authentication or cache the PIN to renew it.
7. A context whose token carries a VCAP permission is held (§5.3) and blocks other clients of the authenticator, including browsers performing WebAuthn sign-in. When the platform has no further operation to perform, it SHOULD release the context with Cancel (§7.3) or by closing the transport.

After a PIN error (`PIN_INVALID`) the context has been zeroized; the platform MUST restart from step 2, first showing the user the balance from getPinRetries, and MUST NOT retry automatically.

### 12.2 Normal Signature

0. Only when this is the first contact with the device, the enterprise has no archived head or counter for the slot, the outcome of the previous operation is unknown, or the enterprise requires it: establish a context (§12.1) with permission READ and call GetState with a challenge newly generated by the enterprise, to obtain a StateProof for step 1.
1. Submit the message to the enterprise (with the StateProof of step 0, if any). The enterprise checks the state basis (§12.8 item 1), **durably stores the message first**, completes content approval and issues a Ticket for the slot's next signature counter. This step does not need the authenticator, so it can happen before the authenticator is connected.
2. Establish a context (§12.1) with permissions READ|SIGN.
3. The platform writes the message to the Outbox (durable storage before signing).
4. If `1 + len(CBOR({1..4,254,255})) ≤ 2048` bytes, use Sign; otherwise use UploadBegin, UploadChunk…, UploadEnd in sequence.
5. Prompt the user to touch once (over NFC, the tap counts as the touch).
6. On receiving Signed, verify the signature independently with the expected public key, and check that originalDigest and originalLength match the Outbox; for a KEL signature also check the expected head.
7. Archive to the enterprise; the UI shows "signed and archived".
8. Network publication and witness acceptance complete in the background; the UI shows "committed locally", "archived by enterprise", "accepted by network" and "business authorized" separately.

Consecutive signatures reuse the valid token, the archived head and consecutive counter values. The authenticator checks the KEL seq / prior and the actual key itself: if the head the enterprise relied on is outdated, Sign returns `INVALID_KERI_EVENT` or `KEY_BINDING` and outputs no signature. That error zeroizes the context and the user must enter the PIN again, so a platform in doubt about its local head SHOULD perform step 0 before requesting a Ticket. A Ticket rejected only because the counter moved (`TICKET_INVALID`) indicates that another signature happened in between; the platform reconciles per §12.3 before requesting a new Ticket.

### 12.3 Lost Response Recovery

The platform **MUST NOT** resend Sign, UploadEnd, CreateIdentity or PrepareRotation. It recovers as follows:

**KEL signatures (ICP / IXN / ROT):**

1. Establish a new context with permission READ.
2. GetState (new challenge); check whether the slot's signature counter equals the Ticket's `signCounter` and the head is the expected seq / said / originalDigest, and check the actual keys (after ROT, current should be old.next).
3. If the head equals the expected event: obtain the message from the Outbox or from the enterprise (authorized retrieval by `(device, slot, said, originalDigest)`) → call Recover with `originalDigest` → verify the returned signature independently against the message → archive.
4. If the head is still the previous event, the earlier signature was not committed; the enterprise decides whether to issue a new Ticket, and the platform MUST NOT re-sign automatically.
5. If a later event already exists, obtain the original signature from the enterprise's historical archive.

**CreateIdentity / PrepareRotation:** check the slot's phase and current / next / prepared keys with GetState; the authenticator generates each key set only once.

**Non-KEL (EXN / RPY / AGENT):** GetState shows whether the counter reached the Ticket's `signCounter`. If it did and no later signature has occurred, Recover with `originalDigest` returns the signature from `lastSigned`. If a later signature has already replaced `lastSigned`, the signature can only come from the enterprise archive or the recipient; a lost response that was never archived cannot be recovered. If the counter did not advance, nothing was signed.

**PIN operations:** query getPinRetries; the user then repeats the operation.

### 12.4 Cancellation

1. When the user cancels while waiting for UP or during an upload, the platform disconnects the transport (or sends Cancel between two commands).
2. The authenticator zeroizes the context; prepared and committed heads are kept.
3. If a signature may have been committed, the platform reconciles read-only per §12.3.

### 12.5 Initial Onboarding (Factory to First Identity)

| Step | Actor | Authenticator command | UP |
|---|---|---|---|
| 1 | Manufacturer | Manufacturing tool creates STOCK, generates attestation identity and issues the certificate chain (offline) | — |
| 2 | Enterprise IT | Verify the certificate chain (Appendix D) and register the attestation public key → confirm with status-mode GetState that the lifecycle is STOCK_UNBOUND → getKeyAgreement → BindEnterprise(tenant, enterprise root key) | 1 |
| 3 | Enterprise IT | getKeyAgreement → Personalize(TrustConfig) | 1 |
| 4 | Employee | getKeyAgreement → setPIN | 0 |
| 5 | Employee | getKeyAgreement → obtain token (READ\|MANAGE\|SIGN) → CreateIdentity(CLIENT) | 0 |
| 6 | Employee | GetState → enterprise issues Ticket → Sign(ICP, CLIENT) | 1 |
| 7 | Enterprise | Create the employee's agent from the archived CLIENT icp and its original signature (for KERIA, the boot request); no additional device signature is needed | 0 |
| 8 | Employee | Sign(IXN, CLIENT): Agent approval | 1 |
| 9 | Employee | CreateIdentity(WORK) → Sign(ICP, WORK) | 1 |
| 10 | Employee | Sign(RPY, WORK): Agent end-role | 1 |

On the native route, steps 4–10 run in one context, so the employee enters the PIN once and touches the authenticator four times, once per signature. The AGENT session (Sign(AGENT, CLIENT), §8.5.3) is not part of onboarding: its claims expire within 300 s, so the platform signs one when it first needs the Agent. On the WebAuthn route (§12.9) each of steps 5, 6, 8, 9 and 10 is one browser call, the two parts of step 9 being separate calls, with one PIN entry and one UP each.

The enterprise MUST reject a device whose lifecycle is not STOCK_UNBOUND at step 2, and MUST perform steps 2 and 3 with devices under its physical control. IT MUST NOT preset or upload employee private keys. In step 7, the enterprise SHOULD recheck the onboarding approval, employee, device and reset epoch, configuration and recipient, and durably record the onboarding operation before calling KERIA to prevent duplicate onboarding. If the response is lost, it reconciles read-only against the CLIENT ICP, the Agent DIP and the mutual ownership, and does not rebuild the Agent when material is missing.

### 12.6 Rotation (WORK)

1. Obtain a token (READ|SIGN).
2. PrepareRotation(slot, challenge) → StateProof; record preparedPublic (newNext). If prepared already exists, the same value is returned.
3. The platform constructs the rot: `k=[old.next]`, `n=[commit(newNext)]`, `s=latest.seq+1`, `p=latest.said`.
4. The enterprise issues a Ticket with `signerKeyRef = KeyRef(old.next)`.
5. Sign(ROT) / upload → one touch → after the authenticator commits, current=old.next, next=newNext, and prepared is deleted.
6. Recover from a lost response per §12.3.

### 12.7 Reset and the New Reset Epoch

1. The enterprise decides on a Reset (departure, lost device, blocked PIN, etc.) and, on the enterprise side, deactivates the old CLIENT / WORK AIDs and stops issuing Tickets for the old reset epoch. Reset also erases the employee's FIDO credentials, so relying parties that registered them need re-registration.
2. Reinsert (USB) or re-tap (NFC) the authenticator and send Reset within 10 s of power-up (§7.12.1 step 2); the user holds the touch for 5 seconds. No PIN is needed, so Reset also works after the PIN is blocked. Generic FIDO clients (browser or operating system settings) can also send Reset and prompt only for a touch; enterprise guidance SHOULD tell users that Reset requires a 5-second hold and erases all identities on the authenticator.
3. On success the authenticator returns to ENTERPRISE_BOUND (resetEpoch+1); IT personalizes again, and the employee sets a PIN and onboards again.
4. The authenticator SHOULD stay connected during Reset; if Reset is interrupted, the authenticator completes it at the next power-up.

A Reset ends the continuity of every AID on the authenticator in the same way as loss of the device; VAF §6.5 specifies the resulting enterprise and credential obligations.

### 12.8 Enterprise Ticket Issuance Requirements

The enterprise Ticket issuer MUST:

1. Use one of the following as the state basis:
   - a fresh StateProof obtained with a challenge **generated by the enterprise and used only once**;
   - the enterprise's archived head and signature counter (from archived Signed results, or a head advanced by network acceptance). For ICP the current / next keys come from the StateProof returned by CreateIdentity, and for ROT newNext comes from the StateProof returned by PrepareRotation.

   The authenticator checks whether the head and counter are current. Slot state cached by the wallet is never a state basis.
2. Durably store the message before issuing the Ticket; audit IDs stay within the enterprise.
3. Fully verify route, receiving domain, risk and content authorization, and reject a message that has duplicate keys in any JSON object; for KEL events also verify the SAID, prior event, witnesses, delegation and network acceptance.
4. Set `signCounter` to the slot's current counter + 1. When it issues another Ticket for a counter value that already has an unused Ticket (for example because the user abandoned the earlier request), it treats the earlier Ticket as still usable until the counter advances, and identifies which message was signed by the `originalDigest` in Signed. When in doubt about device state, require the platform to submit a fresh StateProof.
5. Perform replay protection for non-KEL results at the receiving end as defense in depth (the signature counter already makes each Ticket single-use).
6. When an event is permanently rejected by an authority, mark the slot as REJECTED on the enterprise side only with operational authorization: no further Tickets are issued for the slot in this reset epoch, nothing is rolled back, and no replacement event is signed; the slot can be used again only after Reset. On transient failures, redeliver the original signature.

### 12.9 Browser Procedures

These procedures apply to authenticators that implement the WebAuthn route (§7.14) and use it from a page served on an RP ID listed in `webauthnRpIds`. The browser performs the PIN exchange and context handling of §12.1; the page handles no PIN or token. Browsers do not keep a token from one call to the next, so each `create()` or `get()` call takes one PIN entry and one UP (§7.14.2). The procedures below therefore use one call per operation: the enterprise issues Tickets from its archived state and asks for a wrapped GetState only when that state is in doubt.

#### 12.9.1 Creating an Identity

1. The enterprise generates a single-use challenge.
2. The page calls `navigator.credentials.create()` with the fields of §7.14.4, `attestation: "none"` and `userVerification: "required"`. The user enters the PIN in the browser and touches once.
3. The enterprise verifies the clientDataJSON (`type`, `origin`, `challenge`), extracts the StateProof from the credential public key, verifies it with the registered attestation key, and checks that its challenge equals `SHA-256(clientDataJSON)`.
4. The enterprise records the credential ID as the slot handle together with currentPublic and nextPublic.
5. The StateProof is the state basis for the slot's first Ticket (ICP with `signCounter` 1, §12.8 item 1); the page does not call GetState before signing it.

#### 12.9.2 Signing

1. The page submits the message to the enterprise. The enterprise durably stores it, which serves as the Outbox on this route; checks the state basis and approves the content (§12.8); and returns VCAPREQ (op 1, slot handle, kind, Ticket, message) with a single-use challenge. The state basis is the enterprise's archived state of the slot, which the StateProof of §12.9.1 and the `signCount` and Signed result of every earlier signature keep current, so the page does not call GetState first. A wrapped GetState is needed only when the slot is in doubt (§12.9.3).
2. The page calls `navigator.credentials.get()` with `allowCredentials` containing only VCAPREQ and `userVerification: "required"`. The user enters the PIN and touches once (over NFC, the tap).
3. The enterprise verifies the clientDataJSON, `deviceSig` with the registered attestation key, and the Signed result per §12.2 step 6, and checks that `signCount` equals the Ticket's `signCounter`. It then archives the signature.

#### 12.9.3 Unknown Outcome

Browsers report every authenticator error as a generic failure, so the page cannot tell from a failed `get()` whether a signature was made. When `get()` fails or the page is closed before the result is archived, the enterprise marks the slot in doubt and issues no Ticket for another message on it until it has reconciled per §12.3. On this route reconciliation takes one call, a wrapped GetState (op 2) with key 6 set to the Ticket's `originalDigest` (§7.14.5); on the native route it is a GetState followed by Recover.

- If the counter reached the Ticket's `signCounter` and `Signed` is returned, the enterprise verifies it per §12.2 step 6 and archives it.
- If the counter did not advance, nothing was signed and the Ticket is still valid for the same message. The signature is made only when the user starts it again with a new `get()`; the page MUST NOT repeat it automatically.
- If the counter advanced but `Signed` is null, a later signature has replaced the record and the enterprise proceeds per §12.3.

A user who dismisses the browser dialog causes `CTAPHID_CANCEL`, handled per §12.4.


---

## 13. Security Considerations

### 13.1 Guarantees Provided by the Authenticator

| Threat | Guarantee | Assumptions and limits |
|---|---|---|
| Platform copies private keys through the normal interface | Keys are generated inside the authenticator and the interface has no export | Invasive physical extraction, fault injection and side channels are out of scope |
| Platform silently produces new signatures | Requires a SIGN token (or a `ga` token on the WebAuthn route), a valid Ticket and a new UP | A touch or tap proves presence, not that the content was seen |
| Enterprise signs unilaterally | Role keys only issue Tickets; signing requires the in-authenticator private key and UP | Relies on trusted firmware |
| Employee bypasses enterprise policy | No Ticket, no signature | |
| Rotation to a platform-generated key | k / n / newNext are constrained to in-authenticator keys, and rot is signed with the in-authenticator old.next | Covers rotation only; other forms of long-term takeover are addressed by the enterprise controls of §12.8 |
| Fork within a slot | Events advance strictly by seq / prior, are written before being returned, and latest can only be retrieved as its original signature | Assumes no full rollback of non-volatile storage |
| Duplicate signature after a lost response | Signature counter makes each Ticket single-use; Recover returns the latest and the most recent signature | Older non-KEL signatures only from the enterprise archive |
| Lost device / employee departure | Reset makes the PIN record and all private keys unrecoverable; the enterprise deactivates old AIDs | Network deactivation, secret destruction and external copies are separate matters; historical keys may persist after ROT until Reset |

### 13.2 Remaining Risks

1. **Induced signing:** UP confirms presence only, so the authenticator cannot tell whether the user was induced to sign a well-formed but malicious message. Independent enterprise approval of the message, recipients, attachments, route, receiving domain and deadline is required.
2. **Delayed use of a Ticket:** a Ticket carries no time limit. An issued but unused Ticket remains usable until the slot's next signature, so a compromised platform holding one could sign the approved message later (still needing a PIN token and a user action). The content cannot change, KEL Tickets are bound to the head, and EXN / RPY (`dt`) and AGENT (`expires`) carry their own validity that recipients check. To revoke an unused Ticket, the enterprise has another signature made on the slot, or Resets the authenticator.
3. **NFC tap as UP:** over NFC the tap satisfies UP for one request per field session. A compromised platform that holds a valid PIN token and Ticket can use the user's next tap for its own request, just as it can use a sensor press; a tap also happens when the authenticator is left on a reader. Enterprise approval of the message content remains the control.
4. **FIDO credentials:** the authenticator also holds FIDO credentials for WebAuthn sign-in. They share the PIN and the device but not keys or attestation with VCAP (§7.13), so a relying party cannot link a FIDO credential to the device's VCAP attestation identity.
5. **Slot allocation without a Ticket:** CreateIdentity needs a PIN token but no Ticket, so a compromised platform, or any page served from an RP ID listed in `webauthnRpIds`, can take UNUSED slots until the next Reset; Sign still needs a Ticket. Enterprises detect unexpected slots from StateProofs (§12.8). The enterprise lists only RP IDs whose pages it controls. Pages on other RP IDs cannot detect the VCAP function: the authenticator answers them as a security key without it (§7.14.1).
6. **Browser compatibility:** the WebAuthn route depends on browsers and platform authenticator APIs forwarding the private algorithm identifier, credential IDs of up to 1023 bytes and an opaque `signature` unchanged. Where a platform does not, the native route (§7.4–§7.12) remains available.
7. **Reset by generic FIDO clients:** browser and operating-system settings can send Reset, which erases every identity on the authenticator after a 5-second hold. This follows from CTAP compatibility and is accepted in VCAP 1.0; enterprise guidance tells users what Reset erases (§12.7).

### 13.3 PIN

- The PIN is transmitted only encrypted under pinUvAuthProtocol 2; the authenticator stores only a 16-byte check value and the remaining attempt count (persistent across power loss), and stores neither the PIN nor the token.
- An attempt is decremented before comparison and the counter is restored on success; power loss does not refund an attempt.

### 13.4 Random Numbers

All random values, contextIds, tokens, key agreement private keys and seeds come from a health-tested RNG; an RNG failure returns `INTERNAL` and closes the context.

---

## Appendix A Constants

| Constant | Value |
|---|---|
| FIDO AID (NFC and CCID) | `A0 00 00 06 47 2F 00 01` |
| GetInfo version string | `"VCAP_1_0"` |
| KERI serialization | KERI 1.0 JSON (`KERI10JSON`) |
| Complete request / response limit | 2048 bytes |
| KERI message limit (kind 1..5) | 16 384 bytes |
| AGENT message limit (kind 6) | 512 bytes |
| Ticket | ≤ 512 bytes |
| TrustConfig envelope | ≤ 1536 bytes |
| stateBody | ≤ 1536 bytes |
| Maximum context lifetime | 600 000 ms |
| Token initial usage time limit | 19 800 ms on every transport |
| Token maximum usage period | 600 000 ms (same as the context) |
| UP wait timeout | 30 000 ms |
| Reset power-up window | 10 000 ms |
| UP debounce (release) | 30 ms |
| UP hold duration | Ordinary 30 ms (hold 0); Reset 5000 ms |
| NFC tap as UP | At most one UP-requiring request per field session; never for Reset; no tap over USB HID or CCID |
| PIN length | 1..63 bytes; minPinChars 4..63 |
| Number of slots | 4 |
| TrustConfig roles | 1..8; keyId 1..16 bytes |
| TrustConfig webauthnRpIds | 0..4 |
| VCAP_ALG | -65700 (COSE, private use; WebAuthn route only, provisional) |
| VCAPREQ | ≤ 1023 bytes |
| Slot signature counter | 0..2^32−1 |
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

### C.1 Normative References

- [BCP14] RFC 2119 and RFC 8174, Key words for use in RFCs to Indicate Requirement Levels — <https://www.rfc-editor.org/info/bcp14>
- [CTAP] FIDO Alliance, [Client to Authenticator Protocol (CTAP) 2.3][ctap]: command codes, authenticatorGetInfo, authenticatorClientPIN, PIN/UV Auth Protocol Two, authenticatorReset, status codes, CTAPHID and NFC bindings
- [RFC8949] Concise Binary Object Representation (CBOR), §4.2 Deterministically Encoded CBOR — <https://www.rfc-editor.org/rfc/rfc8949>
- [RFC9052] CBOR Object Signing and Encryption (COSE): Structures and Process — <https://www.rfc-editor.org/rfc/rfc9052>
- [RFC9053] COSE Initial Algorithms — <https://www.rfc-editor.org/rfc/rfc9053>
- [RFC8032] Edwards-Curve Digital Signature Algorithm (EdDSA) — <https://www.rfc-editor.org/rfc/rfc8032>
- [RFC8259] The JavaScript Object Notation (JSON) Data Interchange Format — <https://www.rfc-editor.org/rfc/rfc8259>
- [RFC5869] HMAC-based Extract-and-Expand Key Derivation Function (HKDF) — <https://www.rfc-editor.org/rfc/rfc5869>
- [FIPS180-4] Secure Hash Standard (SHA-256); [FIPS197] AES; [SP800-38A] CBC mode; [FIPS186-5] / [SEC1] P-256
- [ISO7816-4] ISO/IEC 7816-4: APDU structure, command chaining, GET RESPONSE and status words
- [CCID] USB Implementers Forum, *Device Class Specification for USB Chip/Smart Card Interface Devices*, Revision 1.1
- [KERI] Trust over IP, KERI specification, event format of KERI 1.0 (version string `KERI10`) — <https://github.com/trustoverip/kswg-keri-specification>
- [CESR] Trust over IP, CESR specification: qb64 codes `D` and `E` — <https://github.com/trustoverip/kswg-cesr-specification>
- [BLAKE3] The BLAKE3 cryptographic hash function — <https://github.com/BLAKE3-team/BLAKE3-specs>
- [VCAP-EI] VCAP Enterprise Interface 1.0 — <https://vlei-auth.github.io/vcap-ei/>

### C.2 Informative References

- [WEBAUTHN] W3C, Web Authentication Level 3 — <https://www.w3.org/TR/webauthn-3/>
- [VAF] vLEI Authenticator Framework 1.0 — <https://vlei-auth.github.io/vaf/>

[ctap]: https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html
[ctap-commands]: https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html
[ctap-getinfo]: https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorGetInfo
[ctap-clientpin]: https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorClientPIN
[ctap-pinproto2]: https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#pinProto2
[ctap-reset]: https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorReset
[ctap-mc]: https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorMakeCredential
[ctap-ga]: https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorGetAssertion
[ctap-gna]: https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorGetNextAssertion
[ctap-selection]: https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#authenticatorSelection
[ctap-errors]: https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#error-responses
[ctap-usb]: https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#usb
[ctap-nfc]: https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#nfc
[ctap-nfc-getresponse]: https://fidoalliance.org/specs/fido-v2.3-ps-20260226/fido-client-to-authenticator-protocol-v2.3-ps-20260226.html#nfc-ctap-response

## Appendix D Attestation Certificate Chain and Enrollment Records

The attestation identity (§3.1) is an Ed25519 key pair generated at manufacturing together with a certificate chain issued by the manufacturer. The chain is stored in the authenticator but no VCAP command returns it; the manufacturer delivers it to the enterprise for enrollment (VAF §3.1, §9.5).

### D.1 Certificate Chain

```
attestationChain = [+ certificate_bstr]      ; 1..4 entries, leaf first, root last
certificate      = X.509 v3 certificate, DER  ; each ≤ 2048 bytes
```

The deterministic CBOR encoding of `attestationChain` MUST NOT exceed 1400 bytes.

Each certificate MUST satisfy:

| Item | Requirement |
|---|---|
| Encoding | DER; re-encoding the parsed certificate yields the same bytes |
| Subject public key | Ed25519, and a safe public key (§9.1 role.public constraints) |
| Signature algorithm | Ed25519 (OID 1.3.101.112), no parameters, 64-byte signature |
| Issuer | Equals the subject of the next certificate; the last certificate is self-issued |
| Signature | Verifies under the next certificate's public key (the last under its own) |
| Validity | The verification time lies within notBefore..notAfter |
| BasicConstraints | Present. `cA` is FALSE for the leaf and TRUE for every other certificate; if `pathLenConstraint` is present it is not exceeded |
| KeyUsage | If present: `digitalSignature` for the leaf, `keyCertSign` for the others |
| Critical extensions | Only BasicConstraints and KeyUsage may be critical |

A chain of exactly one certificate is a self-issued certificate for the attestation key itself; it then has `cA` TRUE. It is intended for development devices only.

The leaf's public key is `attestationPublic`, and the device identifier is `device = H("VCAP-DEVICE-ID\0" ‖ attestationPublic_raw32)` (§6.3).

### D.2 Verifier Procedure

An enterprise (or any verifier of StateProof) performs the following steps once, at enrollment:

1. Obtain the manufacturer root certificate through a trusted channel independent of the device and of the platform. The root is the trust anchor; it MUST equal the last chain entry byte for byte.
2. Verify the chain per D.1 at the current time.
3. Take `attestationPublic` from the leaf and compute `device`.
4. Bind (device, attestationPublic) to the enrollment record (D.4). Thereafter verify every StateProof and WebAuthn `deviceSig` with that enrolled key (§9.3, §7.14.5).

A verifier MAY also re-verify the chain each time it uses a StateProof. A chain certificate that expires then makes the device unusable for that verifier, so manufacturers SHOULD issue certificates valid for the device's whole service life.

### D.3 Manufacturer Enrollment Package

The manufacturer delivers, for each device:

```
EnrollmentPackage = [1, device_b32, attestationPublic_b32, attestationChain]
```

A manufacturer MUST deliver the enrollment package in this form. The enterprise MUST recompute `device` and `attestationPublic` from the chain (D.2) and reject a package whose fields disagree. The package carries no secret.

### D.4 Enterprise Asset Record (informative)

An enterprise service keeps, after BindEnterprise and Personalize, one public record per device and reset epoch. The following layout is an example:

```
AssetRecord = [1, device_b32, tenant_tstr, resetEpoch, enterpriseRoot_b32,
               attestationPublic_b32, trustConfig_bstr, manufacturerRoot_bstr,
               clientWitnesses[* aid_t44], clientToad]
```

`tenant_tstr` is the enterprise identifier in clear; the device stores only its digest (§6.3). `clientWitnesses` and `clientToad` are the enterprise's witness policy for CLIENT inception. The record is enterprise-internal; the VCAP-EI `registration` operation returns its public subset.

### D.5 Attestation Identity in the Authenticator

The authenticator stores the attestation private key and `attestationChain` in a read-only record written at manufacturing, protected by an integrity check. A record that fails its integrity check puts the authenticator into `RECOVERY_REQUIRED` (§5.1).

## Appendix E Test Vectors

The vectors below are byte-exact values for the derivations and structures of Sections 6, 8 and 9 and for the event syntax of §8.4.3. They are also published as `test-vectors/vcap-1.0-vectors.json`, together with `test-vectors/generate.py`, which reproduces them from the fixed inputs of E.0. All byte strings are lowercase hex.

Signatures are computed with RFC 8032 deterministic Ed25519. VCAP leaves the signing method to the implementation (§8.6), so an authenticator's own signatures over the same input may differ; implementations check them by verification. TrustConfig and Ticket signatures, which the authenticator verifies, are fixed inputs.

### E.0 Inputs

Every private input is `seed(label) = SHA-256("vcap-tv:" ‖ label)`, with the labels attestation, enterprise-root, role-ops, slot0-current, slot0-next, slot1-current, slot1-next, handle-key, pin-token (pinUvAuthToken), challenge, agent-nonce, key-agreement (P-256 scalar = seed mod (n - 1) + 1). The slots are slot 0 (WORK) and slot 1 (CLIENT) of reset epoch 0.

| Input | Value |
|---|---|
| attestationSeed | `d77de77cbf8685c43cbf6063cebe21cbc2d8a3b88018fda727a00c467aeb7dbd` |
| attestationPublic | `39f3eed37dbc97a952cee6c26855e2efb610d7f9c58bc5ae68a14213eba17e61` |
| enterpriseRootSeed | `63c3623cbf9c0b962fe6d222d27b892d97c58da34801c735e5a64f2e7612621b` |
| enterpriseRoot | `637da14a2d51b71f9f014e4b6baa897e1c2930ff142024c8fce252a54fb63b8d` |
| roleSeed(ops) | `4f4248c0dbac867c124636c4446ba72854ae0c04bacd33099df948cfc21639d8` |
| rolePublic(ops) | `9f2d66e383e95880e4564f7f4cb53f705de701a457bafcc629932bb389a35eca` |
| slot0 (WORK) currentSeed | `733dc232c31a44b4743b2aec578b38fc8c9aa3a65203c15fda5881da1424fb5f` |
| slot0 currentPublic | `6a619f5a01d86d569b936810fc5476538b55076dfceffa066b207398b49b8915` |
| slot0 (WORK) nextSeed | `8e8648b7bc38264f49d50e962e19180f6e71748b04e436ca62c279710cf44644` |
| slot0 nextPublic | `228ec3fa95ba54c3ec5bba3d27c235c7245f0ddc3c4fff5c5751dac4ae086d3d` |
| slot1 (CLIENT) currentPublic | `7ca14221c7a974006861637fda5cb3062b5adfee4feb58e43887313771cf0692` |
| slot1 nextPublic | `576f07a58f3368a19da7a5a9153ffe9f64cb1bf613f560b8a7fc8169ea67c574` |
| handleKey | `0d041887d7cf7864d6d577a5b534807ad29f13175de2e28bb08b118276857d2b` |
| pinUvAuthToken | `83eaddd0d8b0571de37099f0b36fa87fcd6a74eb898d4f2e1edde10d1b0baa4c` |
| challenge | `5a84ea3d29fdb36a002309ef83718fb014b8a770a44deb6cb1b85661117b834c` |
| agentNonce | `ed20f342eaf399465cd1e2dbd6316234a597c5d7f4a3c7b2e90d92faaa37ab2a` |
| keyAgreementPrivateScalar | `521f6cb05ab172aca6ad5d25801ab97f98aca8396212d74031ba5c25240fb579` |
| enterpriseIdentifier | `VLEIAUTHEXAMPLE00001` |
| rpId | `vlei.example.com` |
| resetEpoch | `0` |

### E.1 Identifiers

- **device:** `778fff294b90bad5caa009193bc568c71c67a3c256d93b27c5feed3f92c8bfb7`
- **tenant:** `2f58e03d638f73e97fb303bd6e079ae5ccb14830c9355a261482909ffc1f9705`
- **keyAgreement.x:** `4bded8fe009c05552185af797aa1687ddc585de9d6c99e8123dfcf57b839378b`
- **contextId:** `76495aba803ca608fd80dd7c4df72663277232d260d8e673fcacc744caa1c7ee`

### E.2 KERI encodings

- **qb64(D, slot0 current):** `DGphn1oB2G1Wm5NoEPxUdlOLVQdt_O_6Bmsgc5i0m4kV`
- **commit(slot0 next):** `ECe3wQz8UTOFqa6dNnwbc9mQdImudKxh_ZA9maY_pW0M`
- **qb64(D, slot0 next) (commit input, ASCII):** `DCKOw_qVulTD7Fu6PSfCNcckXw3cPE__XFdR2sSuCG09`

### E.3 TrustConfig

body = [2, device, tenant, 0, ownerMask 0x03, minPinChars 6, [['ops', 0x1F23, rolePublic]], [SHA-256(rpId)]]

- **body:**

  ```
  88025820778fff294b90bad5caa009193bc568c71c67a3c256d93b27c5feed3f92c8bfb758202f58e03d638f73e97fb303bd6e079ae5ccb14830c9355a261482909ffc1f97050003068183636f7073191f2358209f2d66e383e95880e4564f7f4cb53f705de701a457bafcc629932bb389a35eca81582002e0ac1700a0b6825d49dc66e31a417183dbba7bc05853be59f465e59dec4d2a
  ```
- **rootSignature:**

  ```
  bcded429480c7803ae3ddf1388ff210931887ab191fe3756d365a90cc881eb411c2e0a3f804db83f4d963013f2736375cf47b5432e3c51ea3bdeee83b22d850f
  ```
- **envelope:**

  ```
  82589788025820778fff294b90bad5caa009193bc568c71c67a3c256d93b27c5feed3f92c8bfb758202f58e03d638f73e97fb303bd6e079ae5ccb14830c9355a261482909ffc1f97050003068183636f7073191f2358209f2d66e383e95880e4564f7f4cb53f705de701a457bafcc629932bb389a35eca81582002e0ac1700a0b6825d49dc66e31a417183dbba7bc05853be59f465e59dec4d2a5840bcded429480c7803ae3ddf1388ff210931887ab191fe3756d365a90cc881eb411c2e0a3f804db83f4d963013f2736375cf47b5432e3c51ea3bdeee83b22d850f
  ```
- **configurationDigest:** `5f87c9ae65d73bce772269f72cf79598911d187b7a090a79bebc661d18cf2b7f`

### E.4 KERI events

- **slot0 icp (UTF-8):**

  ```
  {"v":"KERI10JSON00012b_","t":"icp","d":"EB2eq33B7j9u7XfqHPiYnLGARWwPx0oZjip3UWV7Maz2","i":"EB2eq33B7j9u7XfqHPiYnLGARWwPx0oZjip3UWV7Maz2","s":"0","kt":"1","k":["DGphn1oB2G1Wm5NoEPxUdlOLVQdt_O_6Bmsgc5i0m4kV"],"nt":"1","n":["ECe3wQz8UTOFqa6dNnwbc9mQdImudKxh_ZA9maY_pW0M"],"bt":"0","b":[],"c":[],"a":[]}
  ```
- **slot0 icp length:** `299`
- **slot0 icp originalDigest:** `0de5cedb04f3a767ec3e1388438f8e1db6ede9989c1b7894612f21564b90a415`
- **slot0 AID (= d = i):** `EB2eq33B7j9u7XfqHPiYnLGARWwPx0oZjip3UWV7Maz2`
- **slot0 ixn s=1 (UTF-8):**

  ```
  {"v":"KERI10JSON0000cb_","t":"ixn","d":"EIG_otvN28LG8_WTikcc-pND9e1kW8_TWka4cF9V4q0k","i":"EB2eq33B7j9u7XfqHPiYnLGARWwPx0oZjip3UWV7Maz2","s":"1","p":"EB2eq33B7j9u7XfqHPiYnLGARWwPx0oZjip3UWV7Maz2","a":[]}
  ```
- **slot0 ixn length:** `203`
- **slot0 ixn originalDigest:** `a84fb3d3a24cfab8f5e9c833ef00823b4887a2cdbaf2a21ff0098787c6fc73ab`
- **slot0 ixn SAID:** `EIG_otvN28LG8_WTikcc-pND9e1kW8_TWka4cF9V4q0k`
- **slot1 CLIENT AID:** `EKYc31TwM0SQxtZa6a5rPIdnOdfHhB3ueiebE8haHBa4`

### E.5 KeyRef and Tickets

- **KeyRef(slot 0, WORK, current):** `7ffd6b6997bd11c27e208a78b98d4095618529289856ba8bdf329d53e817e1d4`
- **ICP Ticket body:**

  ```
  86020158207ffd6b6997bd11c27e208a78b98d4095618529289856ba8bdf329d53e817e1d40158200de5cedb04f3a767ec3e1388438f8e1db6ede9989c1b7894612f21564b90a41519012b
  ```
- **ICP Ticket signature:**

  ```
  24522a9a233f4803d1c1aa2a9115e1be4bb4938d04cfd3a0a686405b1fdc0138387210dd7f29c295104f13f8cb6e3503b2d4063a543a68082361a73ff7de5704
  ```
- **ICP Ticket envelope:**

  ```
  83584b86020158207ffd6b6997bd11c27e208a78b98d4095618529289856ba8bdf329d53e817e1d40158200de5cedb04f3a767ec3e1388438f8e1db6ede9989c1b7894612f21564b90a41519012b636f7073584024522a9a233f4803d1c1aa2a9115e1be4bb4938d04cfd3a0a686405b1fdc0138387210dd7f29c295104f13f8cb6e3503b2d4063a543a68082361a73ff7de5704
  ```
- **ICP ticketId (VCAP-EI):** `27bf2fb71f91ae4a5420cfadd0963700`
- **IXN Ticket envelope (signCounter 2):**

  ```
  83584a86020258207ffd6b6997bd11c27e208a78b98d4095618529289856ba8bdf329d53e817e1d4025820a84fb3d3a24cfab8f5e9c833ef00823b4887a2cdbaf2a21ff0098787c6fc73ab18cb636f707358400409c70e3bc3e1a977c8a18194426d55d068f3b00f608cde1bbb616cce51eccc82b01e3e0e4706a764443ce2158f73eb347066dcc575cc6bbdd0b44e5d9c2007
  ```

### E.6 Sign request (ICP, inline)

- **H(CBOR(P)):** `87e852948abb059d3ec4a62f349918f226ac3a240550ceb5d23c7e5026eca50e`
- **auth message:**

  ```
  564341502d434d440076495aba803ca608fd80dd7c4df72663277232d260d8e673fcacc744caa1c7ee5387e852948abb059d3ec4a62f349918f226ac3a240550ceb5d23c7e5026eca50e
  ```
- **pinUvAuthParam:** `4a45bf36c1082563634455a4a762abbe3346b259a66461097301e147ceefb67f`
- **request (command byte + CBOR):**

  ```
  53a60100020103589483584b86020158207ffd6b6997bd11c27e208a78b98d4095618529289856ba8bdf329d53e817e1d40158200de5cedb04f3a767ec3e1388438f8e1db6ede9989c1b7894612f21564b90a41519012b636f7073584024522a9a233f4803d1c1aa2a9115e1be4bb4938d04cfd3a0a686405b1fdc0138387210dd7f29c295104f13f8cb6e3503b2d4063a543a68082361a73ff7de57040459012b7b2276223a224b45524931304a534f4e3030303132625f222c2274223a22696370222c2264223a224542326571333342376a397537586671485069596e4c47415257775078306f5a6a697033555756374d617a32222c2269223a224542326571333342376a397537586671485069596e4c47415257775078306f5a6a697033555756374d617a32222c2273223a2230222c226b74223a2231222c226b223a5b22444770686e316f42324731576d354e6f45507855646c4f4c565164745f4f5f36426d7367633569306d346b56225d2c226e74223a2231222c226e223a5b224543653377517a3855544f46716136644e6e776263396d5164496d75644b78685f5a41396d61595f7057304d225d2c226274223a2230222c2262223a5b5d2c2263223a5b5d2c2261223a5b5d7d18fe0218ff58204a45bf36c1082563634455a4a762abbe3346b259a66461097301e147ceefb67f
  ```
- **request length:** `499`

### E.7 Signed (ICP)

Signature by RFC 8032 deterministic Ed25519; an authenticator's signature may differ and is checked by verification.

- **signature:**

  ```
  1f051fa68d30a483040625b92607a2ac92b0f4ac277279f9c8947f0d2f91a3a898ef252283079b399092b116fdecfe47a925522e5035dc76bd9327f696745601
  ```
- **Signed:**

  ```
  a50158401f051fa68d30a483040625b92607a2ac92b0f4ac277279f9c8947f0d2f91a3a898ef252283079b399092b116fdecfe47a925522e5035dc76bd9327f6967456010258206a619f5a01d86d569b936810fc5476538b55076dfceffa066b207398b49b89150358200de5cedb04f3a767ec3e1388438f8e1db6ede9989c1b7894612f21564b90a4150419012b0501
  ```
- **response:**

  ```
  00a50158401f051fa68d30a483040625b92607a2ac92b0f4ac277279f9c8947f0d2f91a3a898ef252283079b399092b116fdecfe47a925522e5035dc76bd9327f6967456010258206a619f5a01d86d569b936810fc5476538b55076dfceffa066b207398b49b89150358200de5cedb04f3a767ec3e1388438f8e1db6ede9989c1b7894612f21564b90a4150419012b0501
  ```

### E.8 StateProof (after ICP)

slot 0 ACTIVE WORK after the ICP; authState [8, 0, READ|SIGN, 0, 590000]

- **stateBody:**

  ```
  87025820778fff294b90bad5caa009193bc568c71c67a3c256d93b27c5feed3f92c8bfb70058205f87c9ae65d73bce772269f72cf79598911d187b7a090a79bebc661d18cf2b7f58205a84ea3d29fdb36a002309ef83718fb014b8a770a44deb6cb1b85661117b834c850800190300001a000900b0848900020258206a619f5a01d86d569b936810fc5476538b55076dfceffa066b207398b49b89155820228ec3fa95ba54c3ec5bba3d27c235c7245f0ddc3c4fff5c5751dac4ae086d3df6782c4542326571333342376a397537586671485069596e4c47415257775078306f5a6a697033555756374d617a32850100782c4542326571333342376a397537586671485069596e4c47415257775078306f5a6a697033555756374d617a3219012b58200de5cedb04f3a767ec3e1388438f8e1db6ede9989c1b7894612f21564b90a4150189010000f6f6f6f6f60089020000f6f6f6f6f60089030000f6f6f6f6f600
  ```
- **signature:**

  ```
  980b4ad528b94d6d42207597b6c2010628f4498dbbd33a4880e5ccb473d77d84fcc9e15e6a07e6c12d3e4d09f5e9d1d659e1dd46c75d555a518dbf3b33eff70c
  ```
- **StateProof:**

  ```
  a20159016287025820778fff294b90bad5caa009193bc568c71c67a3c256d93b27c5feed3f92c8bfb70058205f87c9ae65d73bce772269f72cf79598911d187b7a090a79bebc661d18cf2b7f58205a84ea3d29fdb36a002309ef83718fb014b8a770a44deb6cb1b85661117b834c850800190300001a000900b0848900020258206a619f5a01d86d569b936810fc5476538b55076dfceffa066b207398b49b89155820228ec3fa95ba54c3ec5bba3d27c235c7245f0ddc3c4fff5c5751dac4ae086d3df6782c4542326571333342376a397537586671485069596e4c47415257775078306f5a6a697033555756374d617a32850100782c4542326571333342376a397537586671485069596e4c47415257775078306f5a6a697033555756374d617a3219012b58200de5cedb04f3a767ec3e1388438f8e1db6ede9989c1b7894612f21564b90a4150189010000f6f6f6f6f60089020000f6f6f6f6f60089030000f6f6f6f6f600025840980b4ad528b94d6d42207597b6c2010628f4498dbbd33a4880e5ccb473d77d84fcc9e15e6a07e6c12d3e4d09f5e9d1d659e1dd46c75d555a518dbf3b33eff70c
  ```

### E.9 WebAuthn route

- **slotHandle (slot 0, WORK):** `5648318300000286867ec34f2153cf3f8421604168f7a0`
- **VCAPREQ GetState (op 2):** `565131a2010202575648318300000286867ec34f2153cf3f8421604168f7a0`
- **rpIdHash:** `02e0ac1700a0b6825d49dc66e31a417183dbba7bc05853be59f465e59dec4d2a`

### E.10 AGENT original (slot 1, CLIENT)

receiver 'agent-gateway.example.com', issued 1793592000, expires +300, walletProfile 'veridian'

- **original:**

  ```
  564341502d4147454e542d53455353494f4e0006454b5963333154774d30535178745a61366135725049646e4f64664868423375656965624538686148426134860178196167656e742d676174657761792e6578616d706c652e636f6d5820ed20f342eaf399465cd1e2dbd6316234a597c5d7f4a3c7b2e90d92faaa37ab2a1a6ae80ac01a6ae80bec4ba10168766572696469616e
  ```
- **length:** `149`
- **originalDigest:** `8c7299b02d28d87656f065fbe0160633c55cba81782f073d5f197b1dfb03a674`

### E.11 Negative Cases

An authenticator rejects each of the following. The Ticket uses the body of E.5; each KERI case keeps the `v` size equal to the message length and violates only the rule named.

- **Ticket signature with S + L (§6.4 rule 1: reject):**

  ```
  83584b86020158207ffd6b6997bd11c27e208a78b98d4095618529289856ba8bdf329d53e817e1d40158200de5cedb04f3a767ec3e1388438f8e1db6ede9989c1b7894612f21564b90a41519012b636f7073584024522a9a233f4803d1c1aa2a9115e1be4bb4938d04cfd3a0a686405b1fdc01382546063a9a8cd4ede6eb0a9baa681418b2d4063a543a68082361a73ff7de5714
  ```
- **icp with a space after ':' (§8.4.3 item 1):**

  ```
  {"v":"KERI10JSON00012c_","t": "icp","d":"EB2eq33B7j9u7XfqHPiYnLGARWwPx0oZjip3UWV7Maz2","i":"EB2eq33B7j9u7XfqHPiYnLGARWwPx0oZjip3UWV7Maz2","s":"0","kt":"1","k":["DGphn1oB2G1Wm5NoEPxUdlOLVQdt_O_6Bmsgc5i0m4kV"],"nt":"1","n":["ECe3wQz8UTOFqa6dNnwbc9mQdImudKxh_ZA9maY_pW0M"],"bt":"0","b":[],"c":[],"a":[]}
  ```
- **icp with kt before s (§8.4.3 item 2):**

  ```
  {"v":"KERI10JSON00012b_","t":"icp","d":"EB2eq33B7j9u7XfqHPiYnLGARWwPx0oZjip3UWV7Maz2","i":"EB2eq33B7j9u7XfqHPiYnLGARWwPx0oZjip3UWV7Maz2","kt":"1","s":"0","k":["DGphn1oB2G1Wm5NoEPxUdlOLVQdt_O_6Bmsgc5i0m4kV"],"nt":"1","n":["ECe3wQz8UTOFqa6dNnwbc9mQdImudKxh_ZA9maY_pW0M"],"bt":"0","b":[],"c":[],"a":[]}
  ```
- **icp with uppercase version hex (§8.4.3 item 3):**

  ```
  {"v":"KERI10JSON00012B_","t":"icp","d":"EB2eq33B7j9u7XfqHPiYnLGARWwPx0oZjip3UWV7Maz2","i":"EB2eq33B7j9u7XfqHPiYnLGARWwPx0oZjip3UWV7Maz2","s":"0","kt":"1","k":["DGphn1oB2G1Wm5NoEPxUdlOLVQdt_O_6Bmsgc5i0m4kV"],"nt":"1","n":["ECe3wQz8UTOFqa6dNnwbc9mQdImudKxh_ZA9maY_pW0M"],"bt":"0","b":[],"c":[],"a":[]}
  ```
- **ixn with s='01' (§8.4.3 item 4):**

  ```
  {"v":"KERI10JSON0000cc_","t":"ixn","d":"EIG_otvN28LG8_WTikcc-pND9e1kW8_TWka4cF9V4q0k","i":"EB2eq33B7j9u7XfqHPiYnLGARWwPx0oZjip3UWV7Maz2","s":"01","p":"EB2eq33B7j9u7XfqHPiYnLGARWwPx0oZjip3UWV7Maz2","a":[]}
  ```
- **icp with escaped t value (§8.4.3 item 5):**

  ```
  {"v":"KERI10JSON000130_","t":"\u0069cp","d":"EB2eq33B7j9u7XfqHPiYnLGARWwPx0oZjip3UWV7Maz2","i":"EB2eq33B7j9u7XfqHPiYnLGARWwPx0oZjip3UWV7Maz2","s":"0","kt":"1","k":["DGphn1oB2G1Wm5NoEPxUdlOLVQdt_O_6Bmsgc5i0m4kV"],"nt":"1","n":["ECe3wQz8UTOFqa6dNnwbc9mQdImudKxh_ZA9maY_pW0M"],"bt":"0","b":[],"c":[],"a":[]}
  ```

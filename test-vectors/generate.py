#!/usr/bin/env python3
"""Generate the VCAP 1.0 test vectors (VCAP Appendix E).

Requires: cryptography, blake3.  Run:  python3 generate.py > vcap-1.0-vectors.json

All private inputs are derived from fixed labels, so every run produces the same
output. Slot and attestation signatures are computed with RFC 8032 deterministic
Ed25519; VCAP does not prescribe the signing method, so an authenticator's own
signatures over the same input may differ and are checked by verification only.
"""
import base64
import hashlib
import hmac
import json
import sys

import blake3
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey)

# ---------------------------------------------------------------- primitives

def H(*parts):
    return hashlib.sha256(b"".join(parts)).digest()


def label_seed(label):
    return H(b"vcap-tv:" + label.encode())


def ed_keypair(seed):
    sk = Ed25519PrivateKey.from_private_bytes(seed)
    pk = sk.public_key().public_bytes(serialization.Encoding.Raw,
                                      serialization.PublicFormat.Raw)
    return sk, pk


def ed_sign(sk, msg):
    return sk.sign(msg)


def ed_verify(pk, sig, msg):
    Ed25519PublicKey.from_public_bytes(pk).verify(sig, msg)


L = 2**252 + 27742317777372353535851937790883648493

# ------------------------------------------------- deterministic CBOR (§6.1)

class Null:
    pass


NULL = Null()


def _head(major, n):
    if n < 24:
        return bytes([major << 5 | n])
    for ai, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
        if n < 1 << (8 * size):
            return bytes([major << 5 | ai]) + n.to_bytes(size, "big")
    raise ValueError(n)


def cbor(x):
    if x is NULL:
        return b"\xf6"
    if x is True:
        return b"\xf5"
    if x is False:
        return b"\xf4"
    if isinstance(x, int):
        return _head(0, x) if x >= 0 else _head(1, -1 - x)
    if isinstance(x, (bytes, bytearray)):
        return _head(2, len(x)) + bytes(x)
    if isinstance(x, str):
        b = x.encode()
        return _head(3, len(b)) + b
    if isinstance(x, list):
        return _head(4, len(x)) + b"".join(cbor(i) for i in x)
    if isinstance(x, dict):
        keys = sorted(x, key=lambda k: cbor(k))
        return _head(5, len(x)) + b"".join(cbor(k) + cbor(x[k]) for k in keys)
    raise TypeError(type(x))

# ------------------------------------------------------- KERI (§6.2, §8.4.3)

def qb64(code, raw32):
    assert len(code) == 1 and len(raw32) == 32
    b = base64.urlsafe_b64encode(b"\x00" + raw32).decode()
    assert len(b) == 44 and b[0] == "A"
    return code + b[1:]


def commit(pub):
    return qb64("E", blake3.blake3(qb64("D", pub).encode()).digest())


def kjson(fields):
    return json.dumps(dict(fields), separators=(",", ":"), ensure_ascii=False)


def keri_event(fields, said_labels):
    """fields: list of (name, value) in KERI 1.0 order, 'v' first."""
    dummy = "#" * 44
    f = [(k, dummy if k in said_labels else v) for k, v in fields]
    f[0] = ("v", "KERI10JSON000000_")
    size = len(kjson(f).encode())
    f[0] = ("v", "KERI10JSON%06x_" % size)
    said = qb64("E", blake3.blake3(kjson(f).encode()).digest())
    f = [(k, said if k in said_labels else v) for k, v in f]
    raw = kjson(f).encode()
    assert len(raw) == size
    return raw, said

# ------------------------------------------------------------------ fixtures

out = {"description": "VCAP 1.0 test vectors (VCAP Appendix E). All byte strings are lowercase hex.",
       "inputs": {}, "vectors": {}, "negative": {}}
I, V, N = out["inputs"], out["vectors"], out["negative"]
hx = lambda b: b.hex()

att_seed = label_seed("attestation")
root_seed = label_seed("enterprise-root")
role_seed = label_seed("role-ops")
s0_cur_seed, s0_next_seed = label_seed("slot0-current"), label_seed("slot0-next")
s1_cur_seed, s1_next_seed = label_seed("slot1-current"), label_seed("slot1-next")
token = label_seed("pin-token")
challenge = label_seed("challenge")
ka_scalar = int.from_bytes(label_seed("key-agreement"), "big") % (
    0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551 - 1) + 1

att_sk, att_pub = ed_keypair(att_seed)
root_sk, root_pub = ed_keypair(root_seed)
role_sk, role_pub = ed_keypair(role_seed)
s0c_sk, s0c_pub = ed_keypair(s0_cur_seed)
_, s0n_pub = ed_keypair(s0_next_seed)
_, s1c_pub = ed_keypair(s1_cur_seed)
_, s1n_pub = ed_keypair(s1_next_seed)

enterprise_id = "VLEIAUTHEXAMPLE00001"
reset_epoch = 0
WORK, CLIENT = 2, 1

I.update({
    "seed derivation": "seed(label) = SHA-256('vcap-tv:' || label)",
    "seed labels": "attestation, enterprise-root, role-ops, slot0-current, slot0-next, slot1-current, slot1-next, pin-token (pinUvAuthToken), challenge, key-agreement (P-256 scalar = seed mod (n - 1) + 1)",
    "attestationSeed": hx(att_seed), "attestationPublic": hx(att_pub),
    "enterpriseRootSeed": hx(root_seed), "enterpriseRoot": hx(root_pub),
    "roleSeed(ops)": hx(role_seed), "rolePublic(ops)": hx(role_pub),
    "slot0 (WORK) currentSeed": hx(s0_cur_seed), "slot0 currentPublic": hx(s0c_pub),
    "slot0 (WORK) nextSeed": hx(s0_next_seed), "slot0 nextPublic": hx(s0n_pub),
    "slot1 (CLIENT) currentPublic": hx(s1c_pub), "slot1 nextPublic": hx(s1n_pub),
    "pinUvAuthToken": hx(token),
    "challenge": hx(challenge),
    "keyAgreementPrivateScalar": "%064x" % ka_scalar,
    "enterpriseIdentifier": enterprise_id, "resetEpoch": reset_epoch,
})

# ---------------------------------------------------- identifiers (§6.3)

device = H(b"VCAP-DEVICE-ID\0", att_pub)
tenant = H(enterprise_id.encode())
ka = ec.derive_private_key(ka_scalar, ec.SECP256R1())
ka_x = ka.public_key().public_numbers().x.to_bytes(32, "big")
context_id = H(b"VCAP-CONTEXT\0", ka_x)
V["E.1 Identifiers"] = {
    "device": hx(device), "tenant": hx(tenant),
    "keyAgreement.x": hx(ka_x), "contextId": hx(context_id),
}

# ------------------------------------------------------ KERI encodings (§6.2)

V["E.2 KERI encodings"] = {
    "qb64(D, slot0 current)": qb64("D", s0c_pub),
    "commit(slot0 next)": commit(s0n_pub),
    "qb64(D, slot0 next) (commit input, ASCII)": qb64("D", s0n_pub),
}

# ---------------------------------------------------------- TrustConfig (§9.1)

roles = [["ops", 0x1F03, role_pub]]
reserved = []  # TrustConfig reserved field: always the empty array
tc_body = cbor([2, device, tenant, reset_epoch, 0x03, 6, roles, reserved])
tc_sig = ed_sign(root_sk, b"VCAP-TRUST\0" + tc_body)
tc_env = cbor([tc_body, tc_sig])
config_digest = H(tc_env)
V["E.3 TrustConfig"] = {
    "content": "body = [2, device, tenant, 0, ownerMask 0x03, minPinChars 6, [['ops', 0x1F03, rolePublic]], []]",
    "body": hx(tc_body), "rootSignature": hx(tc_sig), "envelope": hx(tc_env),
    "configurationDigest": hx(config_digest),
}

# ----------------------------------------------------------- KERI events

icp, aid = keri_event([
    ("v", ""), ("t", "icp"), ("d", ""), ("i", ""), ("s", "0"),
    ("kt", "1"), ("k", [qb64("D", s0c_pub)]), ("nt", "1"), ("n", [commit(s0n_pub)]),
    ("bt", "0"), ("b", []), ("c", []), ("a", []),
], said_labels=("d", "i"))
ixn, ixn_said = keri_event([
    ("v", ""), ("t", "ixn"), ("d", ""), ("i", aid), ("s", "1"), ("p", aid), ("a", []),
], said_labels=("d",))
client_icp, client_aid = keri_event([
    ("v", ""), ("t", "icp"), ("d", ""), ("i", ""), ("s", "0"),
    ("kt", "1"), ("k", [qb64("D", s1c_pub)]), ("nt", "1"), ("n", [commit(s1n_pub)]),
    ("bt", "0"), ("b", []), ("c", []), ("a", []),
], said_labels=("d", "i"))
V["E.4 KERI events"] = {
    "slot0 icp (UTF-8)": icp.decode(), "slot0 icp length": len(icp),
    "slot0 icp originalDigest": hx(H(icp)), "slot0 AID (= d = i)": aid,
    "slot0 ixn s=1 (UTF-8)": ixn.decode(), "slot0 ixn length": len(ixn),
    "slot0 ixn originalDigest": hx(H(ixn)), "slot0 ixn SAID": ixn_said,
    "slot1 CLIENT AID": client_aid,
}

# ------------------------------------------------------------ KeyRef, Ticket

def keyref(slot, owner, pub):
    return H(b"VCAP-KEYREF\0", device, reset_epoch.to_bytes(8, "big"),
             cbor([slot, owner]), pub)


def ticket(kind, kref, counter, msg):
    body = cbor([2, kind, kref, counter, H(msg), len(msg)])
    sig = ed_sign(role_sk, b"VCAP-SIGN\0" + body)
    return body, sig, cbor([body, "ops", sig])


kref0 = keyref(0, WORK, s0c_pub)
t_body, t_sig, t_env = ticket(1, kref0, 1, icp)
t2_body, t2_sig, t2_env = ticket(2, kref0, 2, ixn)
V["E.5 KeyRef and Tickets"] = {
    "KeyRef(slot 0, WORK, current)": hx(kref0),
    "ICP Ticket body": hx(t_body), "ICP Ticket signature": hx(t_sig),
    "ICP Ticket envelope": hx(t_env),
    "ICP ticketId (VCAP-EI)": hx(H(t_env)[:16]),
    "IXN Ticket envelope (signCounter 2)": hx(t2_env),
}

# ------------------------------------------- Sign request authentication (§8.1)

P = {1: 0, 2: 1, 3: t_env, 4: icp}
msg = b"VCAP-CMD\0" + context_id + bytes([0x53]) + H(cbor(P))
pin_param = hmac.new(token, msg, hashlib.sha256).digest()
full = dict(P)
full[254] = 2
full[255] = pin_param
request = bytes([0x53]) + cbor(full)
V["E.6 Sign request (ICP, inline)"] = {
    "H(CBOR(P))": hx(H(cbor(P))), "auth message": hx(msg),
    "pinUvAuthParam": hx(pin_param), "request (command byte + CBOR)": hx(request),
    "request length": len(request),
}

# --------------------------------------------------------------- Signed (§9.4)

icp_sig = ed_sign(s0c_sk, icp)
signed = cbor({1: icp_sig, 2: s0c_pub, 3: H(icp), 4: len(icp), 5: 1})
V["E.7 Signed (ICP)"] = {
    "note": "Signature by RFC 8032 deterministic Ed25519; an authenticator's signature may differ and is checked by verification.",
    "signature": hx(icp_sig), "Signed": hx(signed), "response": "00" + hx(signed),
}

# ----------------------------------------------------------- StateProof (§9.3)

def empty_slot(i):
    return [i, 0, 0, NULL, NULL, NULL, NULL, NULL, 0]


slots = [[0, WORK, 2, s0c_pub, s0n_pub, NULL, aid, [1, 0, aid, len(icp), H(icp)], 1],
         empty_slot(1), empty_slot(2), empty_slot(3)]
auth_state = [8, 0, 0x0300, 0, 590000]
state_body = cbor([2, device, reset_epoch, config_digest, challenge, auth_state, slots])
state_sig = ed_sign(att_sk, b"VCAP-STATE\0" + state_body)
state_proof = cbor({1: state_body, 2: state_sig})
V["E.8 StateProof (after ICP)"] = {
    "content": "slot 0 ACTIVE WORK after the ICP; authState [8, 0, READ|SIGN, 0, 590000]",
    "stateBody": hx(state_body), "signature": hx(state_sig), "StateProof": hx(state_proof),
}

# ------------------------------------------------------------- negative cases

s_int = int.from_bytes(t_sig[32:], "little")
bad_sig = t_sig[:32] + (s_int + L).to_bytes(32, "little")
N["Ticket signature with S + L (§6.4 rule 1: reject)"] = hx(cbor([t_body, "ops", bad_sig]))
icp_text = icp.decode()


def resize(text):
    n = len(text.encode())
    return text[:16] + "%06x" % n + text[22:]


N["icp with a space after ':' (§8.4.3 item 1)"] = resize(icp_text.replace('"t":', '"t": ', 1))
N["icp with kt before s (§8.4.3 item 2)"] = icp_text.replace(',"s":"0","kt":"1"', ',"kt":"1","s":"0"', 1)
N["icp with uppercase version hex (§8.4.3 item 3)"] = icp_text[:16] + icp_text[16:22].upper() + icp_text[22:]
N["ixn with s='01' (§8.4.3 item 4)"] = resize(ixn.decode().replace('"s":"1"', '"s":"01"', 1))
N["icp with escaped t value (§8.4.3 item 5)"] = resize(icp_text.replace('"t":"icp"', '"t":"\\u0069cp"', 1))
N["note"] = "Each negative KERI case keeps the v size equal to the message length, so the named rule is the only violation."

# ------------------------------------------------------------- Binding (§9.5)

binding_vectors = {}
for name, lifecycle, epoch, digest in (
        ("STOCK_UNBOUND", 0, reset_epoch, NULL),
        ("ENTERPRISE_BOUND", 1, reset_epoch + 1, NULL),
        ("PERSONALIZED_NO_PIN", 2, reset_epoch, config_digest)):
    binding = NULL if lifecycle == 0 else [tenant, H(root_pub), epoch, digest]
    binding_body = cbor([2, device, lifecycle, challenge, binding])
    binding_sig = ed_sign(att_sk, b"VCAP-BINDING\0" + binding_body)
    binding_result = cbor({1: binding_body, 2: binding_sig})
    ed_verify(att_pub, binding_sig, b"VCAP-BINDING\0" + binding_body)
    assert len(binding_body) <= 256
    binding_vectors[name] = {
        "request": hx(bytes([0x50]) + cbor({2: challenge})),
        "bindingBody": hx(binding_body), "signature": hx(binding_sig),
        "BindingProof": hx(binding_result), "response": "00" + hx(binding_result),
    }
V["E.12 Binding mode"] = binding_vectors
N["GetState keys 1 and 2"] = {"request": hx(bytes([0x50]) + cbor({1: challenge, 2: challenge})), "status": "02"}
N["Binding mode PIN_READY"] = {"request": hx(bytes([0x50]) + cbor({2: challenge})), "status": "f0"}
mismatch_body = cbor([2, device, tenant, reset_epoch + 1, 0x03, 6, roles, reserved])
mismatch_env = cbor([mismatch_body, ed_sign(root_sk, b"VCAP-TRUST\0" + mismatch_body)])
N["Personalize epoch mismatch"] = {"configuration": hx(mismatch_env), "status": "f8"}

# ------------------------------------------- Group member signing (§8.4.4, §9.4)

B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"


def b64int(n, width):
    return "".join(B64[(n >> (6 * (width - 1 - i))) & 63] for i in range(width))


def indexed_sig(sig, index, ondex=None):
    """CESR indexed Ed25519 signature: A (equal indices < 64), 2A (dual), B (current only)."""
    assert len(sig) == 64
    tail = base64.urlsafe_b64encode(b"\x00\x00" + sig).decode()[2:]
    if ondex is None:
        assert index < 64
        return "B" + b64int(index, 1) + tail
    if index == ondex and index < 64:
        return "A" + b64int(index, 1) + tail
    return "2A" + b64int(index, 2) + b64int(ondex, 2) + tail


m2c_seed, m2n_seed = label_seed("member2-current"), label_seed("member2-next")
_, m2c_pub = ed_keypair(m2c_seed)
_, m2n_pub = ed_keypair(m2n_seed)
s0nn_sk, s0nn_pub = ed_keypair(label_seed("slot0-newnext"))
s0n_sk, _ = ed_keypair(s0_next_seed)

# Group of two members; slot 0 is the second entry, so its index is 1.
g_icp, gaid = keri_event([
    ("v", ""), ("t", "icp"), ("d", ""), ("i", ""), ("s", "0"),
    ("kt", "2"), ("k", [qb64("D", m2c_pub), qb64("D", s0c_pub)]),
    ("nt", "2"), ("n", [commit(m2n_pub), commit(s0n_pub)]),
    ("bt", "0"), ("b", []), ("c", []), ("a", []),
], said_labels=("d", "i"))
# E.13 runs under its own TrustConfig: E.3's role 'ops' (0x1F03) carries no
# group bits, so the same role key is installed with all bits of Appendix B.
g_roles = [["ops", 0x1DF03, role_pub]]
g_tc_body = cbor([2, device, tenant, reset_epoch, 0x03, 6, g_roles, reserved])
g_tc_sig = ed_sign(root_sk, b"VCAP-TRUST\0" + g_tc_body)
g_tc_env = cbor([g_tc_body, g_tc_sig])
g_config_digest = H(g_tc_env)
# Slot 0 signs: own icp (counter 1), group icp under kind 7 (counter 2).
g_t_body, g_t_sig, g_t_env = ticket(7, kref0, 2, g_icp)
g_icp_sig = ed_sign(s0c_sk, g_icp)
g_signed = cbor({1: g_icp_sig, 2: s0c_pub, 3: H(g_icp), 4: len(g_icp), 5: 2})
g_record = [0, gaid, "icp", 0, gaid, len(g_icp), H(g_icp), 2, 0, 0]
g_slots = [[0, WORK, 2, s0c_pub, s0n_pub, NULL, aid, [1, 0, aid, len(icp), H(icp)], 2],
           empty_slot(1), empty_slot(2), empty_slot(3)]
g_state_body = cbor([2, device, reset_epoch, g_config_digest, challenge, auth_state, g_slots, g_record])
g_state_sig = ed_sign(att_sk, b"VCAP-STATE\0" + g_state_body)
g_state_proof = cbor({1: g_state_body, 2: g_state_sig})
g_getstate_P = {1: challenge, 4: gaid}

# Group rot after slot 0 has rotated its own AID (current <- old next, next <- newnext).
# The new member list puts slot 0 first, so its current index (0) differs from its ondex (1).
g_rot, g_rot_said = keri_event([
    ("v", ""), ("t", "rot"), ("d", ""), ("i", gaid), ("s", "1"), ("p", gaid),
    ("kt", "2"), ("k", [qb64("D", s0n_pub), qb64("D", m2n_pub)]),
    ("nt", "2"), ("n", [commit(s0nn_pub), commit(ed_keypair(label_seed("member2-newnext"))[1])]),
    ("bt", "0"), ("br", []), ("ba", []), ("a", []),
], said_labels=("d",))
g_rot_sig = ed_sign(s0n_sk, g_rot)

# Group exn (kind 9): an IPEX grant skeleton sent by the group AID.
g_exn, g_exn_said = keri_event([
    ("v", ""), ("t", "exn"), ("d", ""), ("i", gaid), ("rp", client_aid), ("p", ""),
    ("dt", "2026-11-07T00:00:00.000000+00:00"), ("r", "/ipex/grant"), ("q", {}),
    ("a", {"m": ""}), ("e", {}),
], said_labels=("d",))
g_exn_sig = ed_sign(s0c_sk, g_exn)
# After the StateProof, slot 0 signs the group exn under kind 9 (counter 3).
gx_t_body, gx_t_sig, gx_t_env = ticket(9, kref0, 3, g_exn)
gx_signed = cbor({1: g_exn_sig, 2: s0c_pub, 3: H(g_exn), 4: len(g_exn), 5: 3})

V["E.13 Group member signing"] = {
    "group TrustConfig content": "body = [2, device, tenant, 0, ownerMask 0x03, minPinChars 6, [['ops', 0x1DF03, rolePublic]], []]",
    "group TrustConfig envelope": hx(g_tc_env),
    "group TrustConfig configurationDigest": hx(g_config_digest),
    "member2 currentPublic": hx(m2c_pub), "member2 nextPublic": hx(m2n_pub),
    "group icp (UTF-8)": g_icp.decode(), "group icp length": len(g_icp),
    "group icp originalDigest": hx(H(g_icp)), "group AID": gaid,
    "GROUP Ticket envelope (kind 7, signCounter 2)": hx(g_t_env),
    "GROUP Signed": hx(g_signed),
    "GetState proof-mode parameters with groupAid (before 254/255)": hx(cbor(g_getstate_P)),
    "stateBody with group element": hx(g_state_body),
    "StateProof with group element": hx(g_state_proof),
    "indexed signature, group icp (index 1, code A)": indexed_sig(g_icp_sig, 1, 1),
    "group rot s=1 (UTF-8)": g_rot.decode(),
    "indexed signature, group rot (index 0, ondex 1, code 2A)": indexed_sig(g_rot_sig, 0, 1),
    "indexed signature, current-only code B (form a joining member uses; index 0)": indexed_sig(g_rot_sig, 0),
    "group exn (UTF-8)": g_exn.decode(),
    "indexed signature, group exn (index 1, code A)": indexed_sig(g_exn_sig, 1, 1),
    "GROUP_EXN Ticket envelope (kind 9, signCounter 3)": hx(gx_t_env),
    "GROUP_EXN Signed": hx(gx_signed),
}
ed_verify(root_pub, g_tc_sig, b"VCAP-TRUST\0" + g_tc_body)
ed_verify(role_pub, gx_t_sig, b"VCAP-SIGN\0" + gx_t_body)
assert len(g_tc_env) <= 1536 and len(gx_t_env) <= 512
ed_verify(s0c_pub, g_icp_sig, g_icp)
ed_verify(att_pub, g_state_sig, b"VCAP-STATE\0" + g_state_body)
assert len(g_t_env) <= 512 and len(g_state_body) <= 1536
assert len(indexed_sig(g_icp_sig, 1, 1)) == 88 and len(indexed_sig(g_rot_sig, 0, 1)) == 92
assert len(indexed_sig(g_rot_sig, 0)) == 88

# --------------------------------------------------------------- self-check

ed_verify(root_pub, tc_sig, b"VCAP-TRUST\0" + tc_body)
ed_verify(role_pub, t_sig, b"VCAP-SIGN\0" + t_body)
ed_verify(s0c_pub, icp_sig, icp)
ed_verify(att_pub, state_sig, b"VCAP-STATE\0" + state_body)
assert len(t_env) <= 512 and len(tc_env) <= 1536 and len(state_body) <= 1536
assert len(request) <= 2048

json.dump(out, sys.stdout, indent=2, ensure_ascii=False)
print()

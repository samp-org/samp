"""
SAMP Client Template — send and receive messages on any Substrate chain.

    python main.py                              # interactive (generates a fresh key)
    python main.py --node http://localhost:9944  # connect to a specific node
    SEED=0x<64hex> python main.py               # reuse a specific keypair

Requires: pip install samp
"""
from __future__ import annotations

import json
import os
import sys
import urllib.request
from dataclasses import dataclass
from typing import Any

from samp import (
    Metadata,
    Seed,
    StorageLayout,
    build_signed_extrinsic,
    call_args_from_bytes,
    call_idx_from_int,
    decode_remark,
    encode_public,
    extrinsic_bytes_from_bytes,
    extrinsic_nonce_from_int,
    extract_call,
    extract_signer,
    genesis_hash_from_bytes,
    is_samp_remark,
    pallet_idx_from_int,
    public_from_seed,
    spec_version_from_int,
    sr25519_sign,
    sr25519_signing_scalar,
    tx_version_from_int,
)
from samp.extrinsic import ChainParams
from samp.scale import decode_compact, encode_compact
from samp.ss58 import Ss58Address
from samp.types import Ss58Prefix, ss58_prefix_from_int
from samp.wire import EncryptedRemark, PublicRemark

DEFAULT_NODE = "http://127.0.0.1:9944"


# -- RPC transport (stdlib only) -----------------------------------------------

def rpc(url: str, method: str, params: list[Any] | None = None) -> Any:
    body = json.dumps({"jsonrpc": "2.0", "id": 1, "method": method, "params": params or []})
    req = urllib.request.Request(url, data=body.encode(), headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req) as resp:
        result = json.loads(resp.read())
    if "error" in result:
        raise RuntimeError(f"RPC error: {result['error']}")
    return result["result"]


# -- Chain context -------------------------------------------------------------

@dataclass(frozen=True)
class Chain:
    params: ChainParams
    metadata: Metadata
    remark_pallet: int
    remark_call: int
    nonce_layout: StorageLayout
    ss58_prefix: Ss58Prefix
    name: str


def fetch_chain(url: str) -> Chain:
    genesis_hex: str = rpc(url, "chain_getBlockHash", [0])
    genesis = genesis_hash_from_bytes(bytes.fromhex(genesis_hex.removeprefix("0x")))

    rv = rpc(url, "state_getRuntimeVersion")
    spec = spec_version_from_int(rv["specVersion"])
    tx = tx_version_from_int(rv["transactionVersion"])

    meta_hex: str = rpc(url, "state_getMetadata")
    metadata = Metadata.from_runtime_metadata(bytes.fromhex(meta_hex.removeprefix("0x")))

    idx = metadata.find_call_index("System", "remark")
    if idx is None:
        raise RuntimeError("chain does not have System::remark")
    remark_pallet, remark_call = idx

    nonce_layout = metadata.storage_layout("System", "Account", ["nonce"])

    props = rpc(url, "system_properties")
    prefix = ss58_prefix_from_int(props.get("ss58Format", 42))
    name: str = rpc(url, "system_chain")

    return Chain(
        params=ChainParams(genesis_hash=genesis, spec_version=spec, tx_version=tx),
        metadata=metadata,
        remark_pallet=remark_pallet,
        remark_call=remark_call,
        nonce_layout=nonce_layout,
        ss58_prefix=prefix,
        name=name,
    )


# -- Nonce query ---------------------------------------------------------------

def fetch_nonce(url: str, chain: Chain, pubkey: bytes) -> int:
    import hashlib
    key_hash = hashlib.blake2b(b"System", digest_size=16).digest()
    entry_hash = hashlib.blake2b(b"Account", digest_size=16).digest()
    id_hash = hashlib.blake2b(pubkey, digest_size=16).digest() + pubkey
    storage_key = "0x" + (key_hash + entry_hash + id_hash).hex()
    result: str | None = rpc(url, "state_getStorage", [storage_key])
    if result is None:
        return 0
    data = bytes.fromhex(result.removeprefix("0x"))
    offset = chain.nonce_layout.offset
    width = chain.nonce_layout.width
    if len(data) < offset + width:
        return 0
    return int.from_bytes(data[offset : offset + width], "little")


# -- Send ----------------------------------------------------------------------

def cmd_send(url: str, chain: Chain, seed: Seed, args: list[str]) -> None:
    if len(args) < 2:
        print("Usage: send <recipient_ss58> <message>")
        return
    recipient_ss58, body = args[0], " ".join(args[1:])
    recipient_addr = Ss58Address.parse(recipient_ss58)
    recipient_pubkey = recipient_addr.pubkey()

    remark = encode_public(recipient_pubkey, body)
    call_args = call_args_from_bytes(encode_compact(len(remark)) + remark)

    pubkey = public_from_seed(seed)
    nonce = fetch_nonce(url, chain, bytes(pubkey))
    signer = lambda msg: bytes(sr25519_sign(seed, msg))

    ext = build_signed_extrinsic(
        pallet_idx=pallet_idx_from_int(chain.remark_pallet),
        call_idx=call_idx_from_int(chain.remark_call),
        call_args=call_args,
        public_key=pubkey,
        sign=signer,
        nonce=extrinsic_nonce_from_int(nonce),
        chain_params=chain.params,
    )

    result = rpc(url, "author_submitExtrinsic", ["0x" + bytes(ext).hex()])
    print(f"Submitted: {result}")


# -- Read ----------------------------------------------------------------------

def cmd_read(url: str, chain: Chain, seed: Seed, args: list[str]) -> None:
    count = int(args[0]) if args else 10
    header = rpc(url, "chain_getHeader")
    latest = int(header["number"], 16)
    view_scalar = sr25519_signing_scalar(seed)

    for block_num in range(max(1, latest - count + 1), latest + 1):
        block_hash: str = rpc(url, "chain_getBlockHash", [block_num])
        block = rpc(url, "chain_getBlock", [block_hash])
        for ext_hex in block["block"]["extrinsics"]:
            ext_bytes = bytes.fromhex(ext_hex.removeprefix("0x"))
            ext = extrinsic_bytes_from_bytes(ext_bytes)
            call = extract_call(ext)
            if call is None:
                continue
            if int(call.pallet) != chain.remark_pallet or int(call.call) != chain.remark_call:
                continue
            result = decode_compact(bytes(call.args))
            if result is None:
                continue
            remark_len, offset = result
            remark_data = bytes(call.args)[offset : offset + remark_len]
            if not is_samp_remark(remark_data):
                continue
            sender = extract_signer(ext)
            sender_ss58 = Ss58Address.encode(sender, chain.ss58_prefix).as_str() if sender else "?"
            try:
                remark = decode_remark(remark_data)
            except Exception:
                continue
            if isinstance(remark, PublicRemark):
                recip = Ss58Address.encode(remark.recipient, chain.ss58_prefix).as_str()
                print(f"  #{block_num}  {sender_ss58} \u2192 {recip}  \"{remark.body}\"")
            elif isinstance(remark, EncryptedRemark):
                from samp import check_view_tag, decrypt
                tag = check_view_tag(remark.ciphertext, view_scalar)
                if tag == int(remark.view_tag):
                    try:
                        plain = decrypt(remark.ciphertext, remark.nonce, view_scalar)
                        print(f"  #{block_num}  {sender_ss58} \u2192 you  \"{bytes(plain).decode()}\"")
                    except Exception:
                        print(f"  #{block_num}  {sender_ss58} \u2192 you  [decrypt failed]")
                else:
                    print(f"  #{block_num}  {sender_ss58} \u2192 ?  [encrypted, not for you]")
            else:
                print(f"  #{block_num}  {sender_ss58}  [{type(remark).__name__}]")


# -- Main ----------------------------------------------------------------------

def main() -> None:
    node = DEFAULT_NODE
    argv = sys.argv[1:]
    if "--node" in argv:
        idx = argv.index("--node")
        node = argv[idx + 1]
        argv = argv[:idx] + argv[idx + 2 :]

    seed_hex = os.environ.get("SEED", "")
    if seed_hex:
        seed = Seed.from_bytes(bytes.fromhex(seed_hex.removeprefix("0x")))
    else:
        seed = Seed.from_bytes(os.urandom(32))

    pubkey = public_from_seed(seed)
    print()
    print("SAMP Client Template")
    print("=" * 40)
    print(f"Node: {node}")
    print()

    try:
        chain = fetch_chain(node)
    except Exception as e:
        print(f"Failed to connect: {e}")
        return

    address = Ss58Address.encode(pubkey, chain.ss58_prefix)
    print(f"Chain:   {chain.name} (SS58 prefix {int(chain.ss58_prefix)})")
    print(f"Address: {address.as_str()}")
    if not seed_hex:
        print(f"Seed:    0x{seed.expose_secret().hex()}")
        print("         (random — set SEED env var to reuse)")
    print()
    print("Commands:")
    print("  send <address> <message>   send a public message")
    print("  read [count]               read recent messages (default 10)")
    print("  quit                       exit")
    print()

    while True:
        try:
            line = input("> ").strip()
        except (EOFError, KeyboardInterrupt):
            break
        if not line:
            continue
        parts = line.split(maxsplit=1)
        cmd = parts[0].lower()
        rest = parts[1].split() if len(parts) > 1 else []
        if cmd == "quit" or cmd == "q":
            break
        elif cmd == "send":
            try:
                cmd_send(node, chain, seed, rest)
            except Exception as e:
                print(f"Error: {e}")
        elif cmd == "read":
            try:
                cmd_read(node, chain, seed, rest)
            except Exception as e:
                print(f"Error: {e}")
        else:
            print(f"Unknown command: {cmd}")


if __name__ == "__main__":
    main()

import os
import json
import logging
from typing import Any, Dict, Optional

from flask import Flask, request, jsonify
from web3 import Web3

# -----------------------------------------------------------------------------
# Logging
# -----------------------------------------------------------------------------
logging.basicConfig(level=os.getenv("LOG_LEVEL", "INFO"))
logger = logging.getLogger("clanker_decoder")

# -----------------------------------------------------------------------------
# Config / Paths
# -----------------------------------------------------------------------------
ABI_CLANKER_V31_PATH = os.getenv("ABI_CLANKER_V31_PATH", "abi_clanker.json")   # v3.1 (legacy)
ABI_CLANKER_V40_PATH = os.getenv("ABI_CLANKER_V40_PATH", "abi_clanker_v4.json") # v4.0 (new)

# -----------------------------------------------------------------------------
# Load ABIs
# -----------------------------------------------------------------------------

def _load_json(path: str):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        logger.warning(f"ABI file not found: {path}")
        return None
    except json.JSONDecodeError as e:
        logger.error(f"Invalid JSON in {path}: {e}")
        return None

ABI_CLANKER_V31 = _load_json(ABI_CLANKER_V31_PATH)
ABI_CLANKER_V40 = _load_json(ABI_CLANKER_V40_PATH)

w3 = Web3()

# Build contract interfaces
contract_clanker_v40 = w3.eth.contract(abi=ABI_CLANKER_V40) if ABI_CLANKER_V40 else None
contract_clanker_v31 = w3.eth.contract(abi=ABI_CLANKER_V31) if ABI_CLANKER_V31 else None

# -----------------------------------------------------------------------------
# Helpers
# -----------------------------------------------------------------------------

def _safe_addr(a: Any) -> Any:
    try:
        if isinstance(a, str) and a.startswith("0x") and len(a) == 42:
            return Web3.to_checksum_address(a)
        return a
    except Exception:
        return a

# -----------------------------------------------------------------------------
# Generic decoding pipeline: v4 -> v3.1
# -----------------------------------------------------------------------------

def try_decode_with(contract, input_hex: str):
    if contract is None:
        return None, None
    try:
        func_obj, func_args = contract.decode_function_input(input_hex)
        return func_obj, func_args
    except Exception:
        return None, None


def decode_input_any(input_hex: str) -> Optional[Dict[str, Any]]:
    if not isinstance(input_hex, str):
        return None
    input_hex = input_hex.strip()

    # 1) Clanker v4.0
    func_obj, func_args = try_decode_with(contract_clanker_v40, input_hex)
    if func_obj:
        logger.info(f"[Clanker v4] {func_obj.fn_name}")
        return {
            "function": f"{func_obj.fn_name} (Clanker v4)",
            "args"    : dict(func_args)
        }

    # 2) Clanker v3.1 (legacy)
    func_obj, func_args = try_decode_with(contract_clanker_v31, input_hex)
    if func_obj:
        logger.info(f"[Clanker v3.1] {func_obj.fn_name}")
        return {
            "function": f"{func_obj.fn_name} (Clanker v3.1)",
            "args"    : dict(func_args)
        }

    logger.warning("Cannot decode input with provided ABIs.")
    return None

# -----------------------------------------------------------------------------
# Flask app
# -----------------------------------------------------------------------------
app = Flask(__name__)

@app.get("/")
def health():
    return jsonify({
        "ok": True,
        "message": "Clanker decoder is running",
        "abis": {
            "clanker_v40": bool(ABI_CLANKER_V40),
            "clanker_v31": bool(ABI_CLANKER_V31),
        }
    })

@app.post("/decode")
def decode_endpoint():
    data = request.get_json(force=True, silent=True) or {}
    input_hex = data.get("input") or data.get("data")
    if not input_hex:
        return jsonify({"ok": False, "error": "Missing 'input' (tx data hex)"}), 400

    result = decode_input_any(input_hex)
    if result is None:
        return jsonify({"ok": False, "error": "Unable to decode with v4/v3.1"}), 422

    return jsonify({"ok": True, "decoded": result})

if __name__ == "__main__":
    port = int(os.getenv("PORT", "8000"))
    app.run(host="0.0.0.0", port=port)
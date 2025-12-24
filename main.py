import os
import re
import json
import logging
import requests

from flask import Flask, request, jsonify
from telegram import Bot, Update
from telegram.ext import Dispatcher, CommandHandler, MessageHandler, Filters, CallbackContext
from web3 import Web3
from web3.middleware import geth_poa_middleware
from eth_abi import decode as abi_decode
from eth_utils import keccak

logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger(__name__)

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
API_BASESCAN = os.environ.get("API_BASESCAN")
BASESCAN_API_KEY = os.environ.get("BASESCAN_API_KEY") # use ethscan api
WEBHOOK_URL = os.environ.get("WEBHOOK_URL")
WEB3_PROVIDER_URL = os.environ.get("WEB3_PROVIDER_URL")

if not all([TELEGRAM_BOT_TOKEN, API_BASESCAN, BASESCAN_API_KEY, WEBHOOK_URL, WEB3_PROVIDER_URL]):
    logger.error("❌ Missing environment variables. Please configure TELEGRAM_BOT_TOKEN, API_BASESCAN, BASESCAN_API_KEY, WEBHOOK_URL, WEB3_PROVIDER_URL")
    exit(1)

bot = Bot(token=TELEGRAM_BOT_TOKEN)
dp = Dispatcher(bot, None, use_context=True)

w3 = Web3(
    Web3.HTTPProvider(
        WEB3_PROVIDER_URL,
        request_kwargs={"timeout": 15}
    )
)

# ⚠️ RẤT QUAN TRỌNG: clear middleware mặc định (tránh eth_estimateGas)
w3.middleware_onion.clear()

# Base dùng POA-compatible middleware
w3.middleware_onion.inject(geth_poa_middleware, layer=0)

logger.info("✅ Web3 RPC initialized with middleware cleared (Alchemy-safe)")

try:
    with open("abi_clanker.json", "r", encoding="utf-8") as f:
        abi_clanker_v31 = json.load(f)
    contract_clanker_v31 = None
    logger.info("✅ Clanker v3.1 ABI loaded successfully.")
except Exception as e:
    logger.error(f"❌ Error loading Clanker v3.1 ABI: {e}")
    exit(1)

# Load ABI Clanker v4.0 (optional)
try:
    with open("abi_clanker_v4.json", "r", encoding="utf-8") as f:
        abi_clanker_v40 = json.load(f)
    contract_clanker_v40 = None
    HAS_V4 = True
    logger.info("✅ Clanker v4.0 ABI loaded successfully.")
except Exception as e:
    HAS_V4 = False
    contract_clanker_v40 = None
    logger.warning(f"⚠️ Clanker v4.0 ABI not loaded: {e}. Will decode with v3.1 only.")

# --- deployToken selector for manual decode ---
DEPLOY_TOKEN_SELECTOR = keccak(text=
    "deployToken((address,string,string,bytes32,string,string,string,uint256)"
    ",(address,address,int24,int24,bytes)"
    ",(address,address[],address[],uint16[],int24[],int24[],uint16[],bytes)"
    ",(address,bytes)"
    ",(address,uint256,uint16,bytes)[])"
)[:4].hex()

# --- TokenCreated event signature for event parsing ---
TOKEN_CREATED_EVENT_SIG = keccak(text=
    "TokenCreated(address,address,address,string,string,string,string,string,int24,address,bytes32,address,address,address,uint256,address[])"
).hex()
def parse_token_created_event(txhash: str, contract_address: str) -> dict:
    """
    Parse TokenCreated event from tx receipt (RPC-only, stable)
    """
    logger.info(f"🧪 [DEBUG] Parsing TokenCreated event for tx={txhash}, token={contract_address}")
    try:
        receipt = w3.eth.get_transaction_receipt(txhash)
        logger.info(f"🧪 [DEBUG] Receipt has {len(receipt.get('logs', []))} logs")
        if not receipt:
            return None

        contract_address = Web3.to_checksum_address(contract_address)

        for i, log in enumerate(receipt["logs"]):
            addr = log.get("address")
            topics = log.get("topics", [])
            topic0 = topics[0].hex() if topics else None
            logger.info(
                f"🧪 [DEBUG] log[{i}] address={addr}, topic0={topic0}"
            )
            if not topics:
                continue

            # match TokenCreated event signature (factory emit)
            if topics[0].hex().lower() != TOKEN_CREATED_EVENT_SIG.lower():
                logger.debug(
                    f"🧪 [DEBUG] log[{i}] topic0 mismatch, expected={TOKEN_CREATED_EVENT_SIG}"
                )
                continue
            logger.info(f"🧪 [DEBUG] log[{i}] TokenCreated signature MATCH")

            # OPTIONAL SAFETY: verify tokenAddress in topics[1]
            token_address = Web3.to_checksum_address("0x" + topics[1].hex()[-40:])
            logger.info(
                f"🧪 [DEBUG] log[{i}] tokenAddress={token_address}, target={contract_address}"
            )
            if token_address.lower() != contract_address.lower():
                continue

            token_admin   = Web3.to_checksum_address("0x" + topics[2].hex()[-40:])

            data = bytes.fromhex(log["data"][2:])
            logger.info(
                f"🧪 [DEBUG] log[{i}] data length={len(data)} bytes"
            )

            decoded = abi_decode(
                [
                    "address", # msgSender  ❗ RẤT QUAN TRỌNG
                    "string",  # tokenImage
                    "string",  # tokenName
                    "string",  # tokenSymbol
                    "string",  # tokenMetadata
                    "string",  # tokenContext
                    "int24",   # startingTick
                    "address", # poolHook
                    "bytes32", # poolId
                    "address", # pairedToken
                    "address", # locker
                    "address", # mevModule
                    "uint256", # extensionsSupply
                    "address[]"# extensions
                ],
                data
            )

            (
                msg_sender,
                token_image,
                token_name,
                token_symbol,
                token_metadata,
                token_context,
                starting_tick,
                pool_hook,
                pool_id,
                paired_token,
                locker,
                mev_module,
                extensions_supply,
                extensions
            ) = decoded

            logger.info(
                f"✅ [DEBUG] TokenCreated parsed successfully for {token_address}"
            )
            return {
                "tokenAddress": token_address,
                "tokenAdmin": token_admin,
                "name": token_name,
                "symbol": token_symbol,
                "image": token_image,
                "metadata": token_metadata,
                "context": token_context,
            }

        return None

    except Exception as e:
        logger.exception(f"❌ Failed to parse TokenCreated event: {e}")
        return None

app = Flask(__name__)

ADDRESS_LABELS = {
    "0x2112b8456ac07c15fa31ddf3bf713e77716ff3f9": "bnkr deployer",
    "0xd9acd656a5f1b519c9e76a2a6092265a74186e58": "clanker interface"
}

def get_creation_txhash(contract_address: str) -> str:
    """
    RPC-only method to find contract creation txhash (no API key).
    Steps:
    1) Binary search to find deploy block using eth_getCode
    2) Scan that block to find tx whose receipt.contractAddress == contract
    """
    try:
        logger.info(f"🔍 [RPC] Finding creation txhash for contract {contract_address}")

        contract_address = Web3.to_checksum_address(contract_address)
        latest_block = w3.eth.block_number

        # --- Step 1: binary search deploy block ---
        # Base mainnet chỉ cần search từ block ~5M trở lên
        low, high = 5_000_000, latest_block
        deploy_block = None

        while low <= high:
            mid = (low + high) // 2
            code = w3.eth.get_code(contract_address, mid)
            if code and code != b"":
                deploy_block = mid
                high = mid - 1
            else:
                low = mid + 1

        if deploy_block is None:
            logger.error("❌ [RPC] Could not determine deploy block")
            return None

        logger.info(f"✅ [RPC] Contract deployed at block {deploy_block}")

        # --- Step 2: scan deploy block receipts (CREATE & CREATE2 safe) ---
        block = w3.eth.get_block(deploy_block, full_transactions=True)
        transactions = block.get("transactions") if isinstance(block, dict) else block.transactions

        for tx in transactions:
            try:
                tx_hash = tx.get("hash") if isinstance(tx, dict) else tx.hash
                txhash_hex = tx_hash.hex() if hasattr(tx_hash, "hex") else tx_hash

                receipt = w3.eth.get_transaction_receipt(txhash_hex)

                # CREATE
                if receipt.get("contractAddress") and receipt["contractAddress"].lower() == contract_address.lower():
                    logger.info(f"✅ [RPC] Found creation txhash via receipt.contractAddress: {txhash_hex}")
                    return txhash_hex

                # CREATE2 (factory deploy): check logs address
                for log in receipt.get("logs", []):
                    if log.get("address", "").lower() == contract_address.lower():
                        logger.info(f"✅ [RPC] Found creation txhash via receipt.logs (CREATE2): {txhash_hex}")
                        return txhash_hex

            except Exception:
                continue

        logger.error("❌ [RPC] Creation tx not found in deploy block")
        return None

    except Exception as e:
        logger.exception(f"❌ [RPC] Error finding creation txhash: {e}")
        return None


def get_transaction_data(txhash: str) -> dict:
    """
    RPC-only: fetch transaction data via eth_getTransactionByHash
    Keeps ABI decode logic unchanged.
    """
    try:
        logger.info(f"📦 [RPC] Fetching transaction data for txhash: {txhash}")

        tx = w3.eth.get_transaction(txhash)
        if not tx:
            logger.error("❌ [RPC] Transaction not found")
            return {}

        tx_hash = tx.get("hash") if isinstance(tx, dict) else tx.hash

        raw_input = tx.get("input") if isinstance(tx, dict) else tx["input"]
        # RPC có thể trả input dưới dạng bytes → convert sang hex string
        if isinstance(raw_input, (bytes, bytearray)):
            input_hex = "0x" + raw_input.hex()
        else:
            input_hex = raw_input

        # normalize: tránh 0x0x...
        if isinstance(input_hex, str) and input_hex.startswith("0x0x"):
            input_hex = "0x" + input_hex[4:]

        return {
            "from": tx.get("from") if isinstance(tx, dict) else tx["from"],
            "to": tx.get("to") if isinstance(tx, dict) else tx["to"],
            "input": input_hex,
            "hash": tx_hash.hex() if hasattr(tx_hash, "hex") else tx_hash,
            "blockNumber": tx.get("blockNumber") if isinstance(tx, dict) else tx["blockNumber"],
        }

    except Exception as e:
        logger.exception(f"❌ [RPC] Error fetching transaction data: {e}")
        return {}

def _try_decode(contract, input_hex: str):
    if contract is None:
        return None
    try:
        func_obj, func_args = contract.decode_function_input(input_hex)
        return {"func": func_obj, "args": func_args}
    except Exception:
        return None

def _map_v4_to_v31_like(args_dict: dict) -> dict:
    """
    Chuẩn hóa một phần cấu trúc v4 -> v3.1-like để code cũ có thể hiển thị cơ bản.
    (TokenConfig + một phần Rewards/Locker)
    """
    dc = args_dict.get("deploymentConfig") or args_dict.get(0) or {}
    token_cfg  = dc.get("tokenConfig")  or dc.get(0) or {}
    locker_cfg = dc.get("lockerConfig") or dc.get(2) or {}

    def _get(container, key, idx=None, default=None):
        if isinstance(container, dict):
            return container.get(key, default)
        if isinstance(container, (list, tuple)) and idx is not None:
            try:
                return container[idx]
            except Exception:
                return default
        return default

    token_config_mapped = {
        "tokenAdmin"        : _get(token_cfg, "tokenAdmin", 0),
        "name"              : _get(token_cfg, "name", 1),
        "symbol"            : _get(token_cfg, "symbol", 2),
        "salt"              : _get(token_cfg, "salt", 3),
        "image"             : _get(token_cfg, "image", 4),
        "metadata"          : _get(token_cfg, "metadata", 5),
        "context"           : _get(token_cfg, "context", 6),
        "originatingChainId": _get(token_cfg, "originatingChainId", 7),
    }

    reward_recipients = _get(locker_cfg, "rewardRecipients", 2, [])
    creator_reward_recipient = None
    try:
        if isinstance(reward_recipients, (list, tuple)) and len(reward_recipients) > 0:
            creator_reward_recipient = reward_recipients[0]
    except Exception:
        pass

    mapped = {
        "deploymentConfig": {
            "tokenConfig": token_config_mapped,
            "rewardsConfig": {
                "creatorRewardRecipient": creator_reward_recipient
            }
        }
    }
    return mapped

def decode_input_with_web3(input_hex: str, to_address: str):
    """
    Decode deployToken calldata using eth_abi (web3 decode is NOT reliable here)
    """
    if not input_hex or not input_hex.startswith("0x"):
        return None

    selector = input_hex[2:10]
    if selector != DEPLOY_TOKEN_SELECTOR:
        return None

    payload = bytes.fromhex(input_hex[10:])

    try:
        decoded = abi_decode(
            [
                "("
                "(address,string,string,bytes32,string,string,string,uint256),"
                "(address,address,int24,int24,bytes),"
                "(address,address[],address[],uint16[],int24[],int24[],uint16[],bytes),"
                "(address,bytes),"
                "(address,uint256,uint16,bytes)[]"
                ")"
            ],
            payload
        )
    except Exception as e:
        logger.error(f"❌ eth_abi decode failed: {e}")
        return None

    # unpack
    deployment = decoded[0]

    token_cfg, pool_cfg, locker_cfg, mev_cfg, ext_cfgs = deployment

    token_config = {
        "tokenAdmin": token_cfg[0],
        "name": token_cfg[1],
        "symbol": token_cfg[2],
        "salt": token_cfg[3].hex(),
        "image": token_cfg[4],
        "metadata": token_cfg[5],
        "context": token_cfg[6],
        "originatingChainId": token_cfg[7],
    }

    creator_reward_recipient = None
    try:
        reward_recipients = locker_cfg[2]
        if reward_recipients:
            creator_reward_recipient = reward_recipients[0]
    except Exception:
        pass

    return {
        "function": "deployToken",
        "args": {
            "deploymentConfig": {
                "tokenConfig": token_config,
                "rewardsConfig": {
                    "creatorRewardRecipient": creator_reward_recipient
                }
            }
        }
    }


# --- Clanker v4 RAW calldata decode (LP-mint aware, no event) ---
def decode_clanker_v4_raw(input_hex: str):
    """
    Decode Clanker v4 LP-mint calldata (RPC-only, BaseScan-style)
    Không check selector – decode trực tiếp struct
    """
    try:
        if not input_hex or not input_hex.startswith("0x"):
            return None

        # bỏ 4-byte selector
        payload = bytes.fromhex(input_hex[10:])

        decoded = abi_decode(
            [
                "("
                "(address,string,string,bytes32,string,string,string,uint256),"  # TokenConfig
                "(address,address,int24,int24,bytes),"                           # PoolConfig
                "(address,address[],address[],uint16[],int24[],int24[],uint16[],bytes),"  # LockerConfig
                "(address,bytes),"                                               # MevModuleConfig
                "(address,uint256,uint16,bytes)[]"                               # ExtensionConfigs
                ")"
            ],
            payload
        )

        token_cfg = decoded[0][0]
        locker_cfg = decoded[0][2]

        creator_reward_recipient = None
        try:
            reward_recipients = locker_cfg[2]
            if reward_recipients:
                creator_reward_recipient = reward_recipients[0]
        except Exception:
            pass

        return {
            "tokenConfig": {
                "tokenAdmin": token_cfg[0],
                "name": token_cfg[1],
                "symbol": token_cfg[2],
                "salt": token_cfg[3].hex(),
                "image": token_cfg[4],
                "metadata": token_cfg[5],
                "context": token_cfg[6],
                "originatingChainId": token_cfg[7],
            },
            "creatorRewardRecipient": creator_reward_recipient
        }

    except Exception as e:
        logger.error(f"❌ Clanker v4 raw decode failed: {e}")
        return None


def format_metadata(metadata_raw):
    """
    Trả về chuỗi nhiều dòng để đưa vào Telegram Markdown.
    Chỉ hiển thị các trường không rỗng:
      - description
      - socialMediaUrls: list[{platform, url}]
      - auditUrls: list[str] hoặc list[{label, url}]
    Mỗi dòng có dạng: "<nhãn>: [url](url)" để bấm được.
    """
    lines = []
    try:
        metadata_json = json.loads(metadata_raw) if isinstance(metadata_raw, str) else metadata_raw
    except Exception as e:
        logger.warning(f"Failed to parse metadata JSON: {e}")
        metadata_json = {"raw": metadata_raw}

    if isinstance(metadata_json, dict):
        # 1) description
        desc = metadata_json.get("description")
        if desc and str(desc).strip():
            lines.append(f"description: {desc}")

        # 2) socialMediaUrls
        sm_list = metadata_json.get("socialMediaUrls") or []
        if isinstance(sm_list, (list, tuple)):
            for item in sm_list:
                if not isinstance(item, dict):
                    continue
                platform = (item.get("platform") or "link").strip()
                url = (item.get("url") or "").strip()
                if url:
                    lines.append(f"{platform}: [{url}]({url})")

        # 3) auditUrls
        audit_list = metadata_json.get("auditUrls") or []
        if isinstance(audit_list, (list, tuple)):
            for a in audit_list:
                if isinstance(a, dict):
                    label = (a.get("label") or "audit").strip()
                    url = (a.get("url") or "").strip()
                    if url:
                        lines.append(f"{label}: [{url}]({url})")
                elif isinstance(a, str):
                    if a.strip():
                        lines.append(f"audit: [{a}]({a})")
    else:
        # Fallback: in nguyên nếu không phải dict
        if metadata_json:
            lines.append(str(metadata_json))

    return "\n".join(lines)

def handle_message(update: Update, context: CallbackContext):
    try:
        msg_text = update.message.text.strip()
        logger.info(f"📨 Received message: {msg_text}")
        logger.info(f"🧪 [DEBUG] Using Clanker v4 RAW calldata decode (LP-mint aware)")

        if not re.match(r"^0x[a-fA-F0-9]{40}$", msg_text):
            logger.warning("⚠️ Message is not a valid contract address.")
            return

        update.message.reply_text(f"Processing contract: `{msg_text}`", parse_mode="Markdown")
        txhash = get_creation_txhash(msg_text)
        if not txhash:
            update.message.reply_text("Could not find creation transaction via RPC.")
            return

        tx_data = get_transaction_data(txhash)
        if not tx_data:
            update.message.reply_text("Failed to retrieve transaction data via RPC.")
            return

        from_address = tx_data.get("from", "")
        if not from_address:
            update.message.reply_text("No 'from' address found in the transaction.")
            return

        label = ADDRESS_LABELS.get(from_address.lower())
        display_from = f"{label} ({from_address})" if label else from_address

        input_data_raw = tx_data.get("input", "")
        if not input_data_raw:
            update.message.reply_text("No input data found in the transaction.")
            return

        logger.info(f"🔍 Input data raw (first 20 chars): {input_data_raw[:20]}... (length: {len(input_data_raw)})")

        # --- Decode Clanker v4 LP-mint calldata ---
        decoded = decode_clanker_v4_raw(input_data_raw)
        if not decoded:
            update.message.reply_text("Failed to decode Clanker v4 calldata.")
            return

        token_config = decoded.get("tokenConfig", {})
        creator_reward_recipient = decoded.get("creatorRewardRecipient")

        name = token_config.get("name")
        symbol = token_config.get("symbol")
        if symbol and not str(symbol).startswith("$"):
            symbol = f"${symbol}"
        image = token_config.get("image")

        # Parse context (giữ logic cũ)
        context_raw = token_config.get("context")
        try:
            context_json = json.loads(context_raw) if isinstance(context_raw, str) else context_raw
        except Exception as e:
            logger.warning(f"Failed to parse context JSON: {e}")
            context_json = {"context": context_raw}

        context_lines = []
        if isinstance(context_json, dict):
            for key, value in context_json.items():
                if value and str(value).strip():
                    if key == "messageId":
                        context_lines.append(f"{key}: [Link]({value})")
                    elif key == "id":
                        continue
                    else:
                        context_lines.append(f"{key}: {value}")
        else:
            context_lines.append(str(context_json))
        context_formatted = "\n".join(context_lines)

        # NEW: parse & format metadata (v4/v3.1 nếu có)
        metadata_raw = token_config.get("metadata")
        metadata_formatted = ""
        if metadata_raw:
            metadata_formatted = format_metadata(metadata_raw)

        # Trả lời: giữ cấu trúc cũ + chèn Metadata nếu có
        reply = (
            "*CLANKER Information:*\n\n"
            f"*From:* `{display_from}`\n"
            f"*Name:* `{name}`\n"
            f"*Symbol:* `{symbol}`\n"
            f"*Image:* [Link]({image})\n\n"
            f"*Context:*\n{context_formatted}\n\n"
        )

        if metadata_formatted:
            reply += f"*Metadata(Check lại cẩn thận, có thể fake):*\n{metadata_formatted}\n\n"

        reply += f"*Creator Reward Recipient:* `{creator_reward_recipient}`"

        update.message.reply_text(reply, parse_mode="Markdown")
        logger.info("✅ Bot has responded successfully.")

    except Exception as e:
        logger.exception(f"❌ Unhandled error in handle_message: {e}")

def start_command(update: Update, context: CallbackContext):
    update.message.reply_text("Bot is ready. Please send a token contract address to process.")

dp.add_handler(CommandHandler("start", start_command))
dp.add_handler(MessageHandler(Filters.text & ~Filters.command, handle_message))

@app.route(f"/{TELEGRAM_BOT_TOKEN}", methods=["POST"])
def telegram_webhook():
    try:
        data = request.get_json(force=True)
        logger.info(f"📨 Received update from Telegram: {data}")
        update_obj = Update.de_json(data, bot)
        dp.process_update(update_obj)
        return jsonify({"ok": True})
    except Exception as e:
        logger.exception(f"❌ Error processing webhook: {e}")
        return jsonify({"ok": False}), 500

@app.route("/", methods=["GET"])
def index():
    return "🤖 Clanker Bot is running (Flask webhook)."

def main():
    bot.delete_webhook(drop_pending_updates=True)
    hook_url = f"{WEBHOOK_URL}/{TELEGRAM_BOT_TOKEN}"
    if not bot.set_webhook(url=hook_url):
        logger.error("❌ Failed to set webhook with Telegram.")
        exit(1)
    logger.info(f"✅ Webhook has been set: {hook_url}")

    port = int(os.environ.get("PORT", 80))
    logger.info(f"🚀 Starting Flask server on port {port}...")
    app.run(host="0.0.0.0", port=port)

if __name__ == "__main__":
    main()
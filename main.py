import os
import re
import json
import logging
import requests

from flask import Flask, request, jsonify
from telegram import Bot, Update
from telegram.ext import Dispatcher, CommandHandler, MessageHandler, Filters, CallbackContext
from web3 import Web3

logging.basicConfig(
    format="%(asctime)s - %(levelname)s - %(message)s",
    level=logging.INFO
)
logger = logging.getLogger(__name__)

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")
API_BASESCAN = os.environ.get("API_BASESCAN")  # e.g. "https://api.basescan.org"
BASESCAN_API_KEY = os.environ.get("BASESCAN_API_KEY")
WEBHOOK_URL = os.environ.get("WEBHOOK_URL")        # e.g. "https://get-clank-production.up.railway.app"
WEB3_PROVIDER_URL = os.environ.get("WEB3_PROVIDER_URL")  # e.g. "https://mainnet.infura.io/v3/YOUR_INFURA_PROJECT_ID"

if not all([TELEGRAM_BOT_TOKEN, API_BASESCAN, BASESCAN_API_KEY, WEBHOOK_URL, WEB3_PROVIDER_URL]):
    logger.error("❌ Missing environment variables. Please configure TELEGRAM_BOT_TOKEN, API_BASESCAN, BASESCAN_API_KEY, WEBHOOK_URL, WEB3_PROVIDER_URL")
    exit(1)

bot = Bot(token=TELEGRAM_BOT_TOKEN)
dp = Dispatcher(bot, None, use_context=True)

w3 = Web3(Web3.HTTPProvider(WEB3_PROVIDER_URL))

try:
    with open("abi_clanker.json", "r") as f:
        abi_clanker = json.load(f)
    contract_clanker = w3.eth.contract(abi=abi_clanker)
    logger.info("✅ Clanker ABI loaded successfully.")
except Exception as e:
    logger.error(f"❌ Error loading Clanker ABI: {e}")
    exit(1)

try:
    with open("abi_revealcam.json", "r") as f:
        abi_revealcam = json.load(f)
    contract_revealcam = w3.eth.contract(abi=abi_revealcam)
    logger.info("✅ Revealcam ABI loaded successfully.")
except Exception as e:
    logger.error(f"❌ Error loading Revealcam ABI: {e}")
    exit(1)

app = Flask(__name__)

ADDRESS_LABELS = {
    "0x2112b8456ac07c15fa31ddf3bf713e77716ff3f9": "bnkr deployer",
    "0xd9acd656a5f1b519c9e76a2a6092265a74186e58": "clanker interface"
}

def get_creation_txhash(contract_address: str) -> str:
    try:
        logger.info(f"🔍 Getting creation txhash from BaseScan for contract {contract_address}")
        url = f"{API_BASESCAN}/api"
        params = {
            "module": "contract",
            "action": "getcontractcreation",
            "contractaddresses": contract_address,
            "apikey": BASESCAN_API_KEY
        }
        resp = requests.get(url, params=params, timeout=10)
        data = resp.json()
        results = data.get("result", [])
        if not results or not isinstance(results, list):
            logger.error(f"❌ No result for contract {contract_address}")
            return None
        txhash = results[0].get("txHash")
        logger.info(f"✅ Found txhash: {txhash}")
        return txhash
    except Exception as e:
        logger.error(f"❌ Error fetching txhash: {e}")
        return None

def get_transaction_data(txhash: str) -> dict:
    try:
        logger.info(f"📦 Fetching transaction data for txhash: {txhash}")
        url = f"{API_BASESCAN}/api"
        params = {
            "module": "proxy",
            "action": "eth_getTransactionByHash",
            "txhash": txhash,
            "apikey": BASESCAN_API_KEY
        }
        resp = requests.get(url, params=params, timeout=10)
        data = resp.json()
        logger.info("✅ Transaction data retrieved.")
        return data.get("result", {})
    except Exception as e:
        logger.error(f"❌ Error fetching transaction data: {e}")
        return {}

def decode_input_with_web3(input_hex: str):
    try:
        logger.info("🔓 Decoding input data with Clanker ABI...")
        func_obj, func_args = contract_clanker.decode_function_input(input_hex)
        logger.info(f"✅ Decoded function: {func_obj.fn_name}")
        return {"function": func_obj.fn_name, "args": func_args}
    except Exception as e:
        logger.error(f"❌ Error decoding input with Clanker ABI: {e}")
        return None

def decode_input_with_web3_revealcam(input_hex: str):
    try:
        logger.info("🔓 Decoding input data with Revealcam ABI...")
        func_obj, func_args = contract_revealcam.decode_function_input(input_hex)
        logger.info(f"✅ Decoded function: {func_obj.fn_name}")
        return {"function": func_obj.fn_name, "args": func_args}
    except Exception as e:
        logger.error(f"❌ Error decoding input with Revealcam ABI: {e}")
        return None

def handle_message(update: Update, context: CallbackContext):
    try:
        msg_text = update.message.text.strip()
        logger.info(f"📨 Received message: {msg_text}")

        if not re.match(r"^0x[a-fA-F0-9]{40}$", msg_text):
            logger.warning("⚠️ Message is not a valid contract address.")
            return

        update.message.reply_text(f"Processing contract: `{msg_text}`", parse_mode="Markdown")
        txhash = get_creation_txhash(msg_text)
        if not txhash:
            update.message.reply_text("Could not find txhash from BaseScan.")
            return

        tx_data = get_transaction_data(txhash)
        if not tx_data:
            update.message.reply_text("Failed to retrieve transaction data from BaseScan.")
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

        decoded = decode_input_with_web3(input_data_raw)

        abi_used = "clanker"
        if not decoded or decoded.get("function") != "deployToken":
            # thử với revealcam
            decoded_rc = decode_input_with_web3_revealcam(input_data_raw)
            if decoded_rc and decoded_rc.get("function") == "deployToken":
                decoded = decoded_rc
                abi_used = "revealcam"
            else:
                update.message.reply_text("Error decoding input data with known ABIs.")
                return

        if abi_used == "revealcam":
            args = decoded.get("args", {})
            name = args.get("_name") or args.get("name")
            symbol = args.get("_symbol") or args.get("symbol")
            if symbol and not symbol.startswith("$"):
                symbol = f"${symbol}"
            fid = args.get("_fid") or args.get("fid")
            image = args.get("_image") or args.get("image")
            deployer = args.get("_deployer") or args.get("deployer")

            reply = (
                "*REVEALCAM Information:*\n\n"
                f"*From:* `{display_from}`\n"
                f"*Name:* `{name}`\n"
                f"*Symbol:* `{symbol}`\n"
                f"*FID:* `{fid}`\n"
                f"*Image:* [Link]({image})\n\n"
                f"*Deployer:* `{deployer}`"
            )
        else:
            args = decoded.get("args", {}).get("deploymentConfig", {})
            token_config = args.get("tokenConfig", {})
            rewards_config = args.get("rewardsConfig", {})

            name = token_config.get("name")
            symbol = token_config.get("symbol")
            if symbol and not symbol.startswith("$"):
                symbol = f"${symbol}"
            image = token_config.get("image")
            creator_reward_recipient = rewards_config.get("creatorRewardRecipient")

            context_raw = token_config.get("context")
            try:
                context_json = json.loads(context_raw)
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

            reply = (
                "*CLANKER Information:*\n\n"
                f"*From:* `{display_from}`\n"
                f"*Name:* `{name}`\n"
                f"*Symbol:* `{symbol}`\n"
                f"*Image:* [Link]({image})\n\n"
                f"*Context:*\n{context_formatted}\n\n"
                f"*Creator Reward Recipient:* `{creator_reward_recipient}`"
            )

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
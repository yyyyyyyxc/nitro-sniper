import asyncio, aiohttp, re, random, logging, os
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler

TOKENS_FILE = "tokens.txt"          
PROXIES_FILE = "proxies.txt"        
WEBHOOK_URL = ""                    
MAX_REDEEMS_PER_HOUR = 3
BASE_DELAY = 2.0
JITTER = 0.5
LEVENSHTEIN_THRESHOLD = 2
MIN_ACCOUNT_AGE_DAYS = 7

PHISHING_DOMAINS = set([
    
    "discord-nitro.ru", "discordgift.ru", "discord-gifts.com",
    "discord-app.net", "dlscord.com", "disc0rd.com", "d1scord.com",
    "discord-giveaway.xyz", "discordfree.com", "claim-discord.com",
    "discordnitro.xyz", "nitrodiscord.com", "discordpromo.net",
    "steam-discord.com", "disord-gift.com", "discordc.com",
    "discrod.com", "discorcl.com", "discord-gift.org",
    "discord-gifts.ru", "gift-discord.com", "freerobux.com",
    
    "bit.ly", "tinyurl.com", "ow.ly", "is.gd", "buff.ly",      
    "shorturl.at", "rb.gy", "t.co", "goo.gl", "shorte.st",
    "adf.ly", "bc.vc", "lnkd.in", "t2m.io", "cutt.ly",
])


logger = logging.getLogger("NitroSniper")
logger.setLevel(logging.INFO)
handler = RotatingFileHandler("sniper.log", maxBytes=5*1024*1024, backupCount=3)
fmt = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
handler.setFormatter(fmt)
logger.addHandler(handler)
console_handler = logging.StreamHandler()
console_handler.setFormatter(fmt)
logger.addHandler(console_handler)


OFFICIAL_DOMAINS = ["discord.gift", "discord.com/gifts", "discordapp.com/gifts"]


GIFT_REGEX = re.compile(r"https?://(?:discord\.gift|discord(?:app)?\.com/gifts?)/([a-zA-Z0-9]{16,24})")


def levenshtein(a: str, b: str) -> int:
    m, n = len(a), len(b)
    dp = [[0]*(n+1) for _ in range(m+1)]
    for i in range(m+1):
        dp[i][0] = i
    for j in range(n+1):
        dp[0][j] = j
    for i in range(1, m+1):
        for j in range(1, n+1):
            dp[i][j] = dp[i-1][j-1] if a[i-1] == b[j-1] else 1 + min(dp[i-1][j], dp[i][j-1], dp[i-1][j-1])
    return dp[m][n]

def is_typosquatting(domain: str) -> bool:
    domain = domain.lower().replace("https://", "").replace("http://", "").split("/")[0]
    for official in ["discord.gift", "discord.com", "discordapp.com"]:
        if levenshtein(domain, official) <= LEVENSHTEIN_THRESHOLD and domain != official:
            return True
    return False


def load_lines(filename: str):
    if not os.path.exists(filename):
        return []
    with open(filename, "r", encoding="utf-8") as f:
        return [line.strip() for line in f if line.strip()]

tokens = load_lines(TOKENS_FILE)
proxies = load_lines(PROXIES_FILE)

if not tokens:
    logger.error("V tokens.txt nic není!")
    exit(1)

logger.info(f"Mám {len(tokens)} tokenů, {len(proxies)} proxy, {len(PHISHING_DOMAINS)} phishing domén")


class RateLimiter:
    def __init__(self, max_per_hour):
        self.max_per_hour = max_per_hour
        self.history = {}

    def is_limited(self, token: str):
        now = datetime.now()
        if token not in self.history:
            self.history[token] = []
        self.history[token] = [t for t in self.history[token] if now - t < timedelta(hours=1)]
        return len(self.history[token]) >= self.max_per_hour

    def record(self, token: str):
        if token not in self.history:
            self.history[token] = []
        self.history[token].append(datetime.now())

limiter = RateLimiter(MAX_REDEEMS_PER_HOUR)


async def redeem_code(session: aiohttp.ClientSession, token: str, code: str) -> bool:
    headers = {
        "Authorization": token,
        "User-Agent": random.choice([
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/125.0.0.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Edg/125.0.0.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0"
        ]),
        "Content-Type": "application/json"
    }
    payload = {"channel_id": None}
    try:
        proxy = random.choice(proxies) if proxies else None
        async with session.post(
            f"https://discord.com/api/v9/entitlements/gift-codes/{code}/redeem",
            headers=headers,
            json=payload,
            proxy=proxy,
            timeout=10
        ) as resp:
            if resp.status == 200:
                logger.info(f"NITRO ZÍSKÁNO: {code}, token {token[:10]}...")
                return True
            else:
                data = await resp.json()
                msg = data.get("message", "?")
                logger.info(f"Kód {code} selhal: {msg}")
                return False
    except Exception as e:
        logger.error(f"Síťová chyba: {e}")
        return False


async def process_message(session: aiohttp.ClientSession, token: str, content: str, author_info: str):
   
    if re.search(r"https?://(?:bit\.ly|tinyurl\.com|ow\.ly|is\.gd|buff\.ly|shorturl\.at|rb\.gy|t\.co|goo\.gl|shorte\.st|adf\.ly|bc\.vc|lnkd\.in|t2m\.io|cutt\.ly|x\.co|v\.gd|zee\.gl|short\.gy|rotf\.lol|href\.li)", content):
        logger.debug(f"Zkracovač URL ignorován: {content[:50]}")
        return

    
    if is_typosquatting(content):
        logger.warning(f"Typosquatting: {content[:50]}")
        return

    
    for dom in PHISHING_DOMAINS:
        if dom in content.lower():
            logger.warning(f"Phishing doména {dom} v: {content[:50]}")
            return

    
    for match in GIFT_REGEX.finditer(content):
        code = match.group(1)
        logger.info(f"Nalezen kód: {code} od {author_info}")
        if limiter.is_limited(token):
            logger.warning(f"Rate‑limit pro token {token[:10]}..., kód ignorován")
            return
        success = await redeem_code(session, token, code)
        limiter.record(token)
        if success and WEBHOOK_URL:
            await notify_webhook(session, code, author_info)
        await asyncio.sleep(random.uniform(BASE_DELAY - JITTER, BASE_DELAY + JITTER))

async def notify_webhook(session: aiohttp.ClientSession, code: str, author: str):
    embed = {
        "title": "Nitro získán!",
        "description": f"**Kód:** {code}\n**Zdroj:** {author}",
        "color": 0x00ff00,
        "footer": {"text": "Nitro Sniper"}
    }
    try:
        await session.post(WEBHOOK_URL, json={"embeds": [embed]})
    except Exception as e:
        logger.error(f"Webhook selhal: {e}")


import discord
from discord.ext import commands

class NitroSniperBot(commands.Bot):
    def __init__(self, token: str, session: aiohttp.ClientSession):
        self.token = token
        self.session = session
        super().__init__(command_prefix="!", self_bot=True)

    async def on_ready(self):
        logger.info(f"Přihlášen jako {self.user} (ID: {self.user.id})")

    async def on_message(self, message):
        if message.author == self.user or not message.guild:
            return
        acc_age = (datetime.now().astimezone() - message.author.created_at.replace(tzinfo=None)).days
        if acc_age < MIN_ACCOUNT_AGE_DAYS:
            return
        await process_message(self.session, self.token, message.content,
                              f"{message.author.name}#{message.author.discriminator}")


async def main():
    session = aiohttp.ClientSession()
    tasks = []
    for token in tokens:
        bot = NitroSniperBot(token, session)
        tasks.append(asyncio.create_task(bot.start(token, reconnect=True)))
    await asyncio.gather(*tasks)

if __name__ == "__main__":
    asyncio.run(main())

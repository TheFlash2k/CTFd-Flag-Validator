from discordwebhook import Discord as DiscordWebhook
import os
from .logger import logger

class Discord:

    ''' Simple WebHook api to send data to a Discord channel '''
    def post(content: str, err=False):
        webhook = os.getenv("DISCORD_WEBHOOK_URL", "")
        if not webhook:
            if err:
                raise Exception("DISCORD_WEBHOOK_URL is not set")
            else:
                logger.warning("DISCORD_WEBHOOK_URL is not set. Skipping...")
                return
        DiscordWebhook(url=webhook).post(content=content)
        logger.info(f"Posted \"{content}\" to Discord")
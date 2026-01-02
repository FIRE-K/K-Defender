from telethon import TelegramClient
from telethon.sessions import StringSession
import os

import dotenv
dotenv.load_dotenv()

API_ID = int(os.getenv('API_ID'))
API_HASH = os.getenv('API_HASH')
session = StringSession()

with TelegramClient(session, API_ID, API_HASH) as client:
    print('Your session string (save in .env:')
    print(session.save())
from __future__ import annotations
from dotenv import load_dotenv
from app.config import Config
from app.bot_flow import build_app

def main():
    load_dotenv()
    cfg = Config.from_env()
    app = build_app(cfg)
    app.run_polling(allowed_updates=["message"])

if __name__ == "__main__":
    main()

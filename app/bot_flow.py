from __future__ import annotations

import asyncio
import os
from telegram import Update, ReplyKeyboardMarkup, ReplyKeyboardRemove
from telegram.ext import (
    Application, CommandHandler, MessageHandler, ContextTypes,
    ConversationHandler, filters
)

from app.config import Config
from app import integrations

CHOOSE_ITEM, CHOOSE_TARGET = range(2)

def _is_allowed(update: Update, cfg: Config) -> bool:
    if not cfg.allowed_chat_ids:
        return True  # jeśli puste, pozwól wszystkim (możesz odwrotnie, jeśli wolisz)
    return update.effective_chat and update.effective_chat.id in cfg.allowed_chat_ids

def _targets_keyboard(cfg: Config) -> ReplyKeyboardMarkup:
    # pokazujemy jako: "1", "2", "3" w klawiaturze
    buttons = [[str(i)] for i in range(1, len(cfg.save_targets) + 1)]
    return ReplyKeyboardMarkup(buttons, resize_keyboard=True, one_time_keyboard=True)

async def cmd_start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    cfg: Config = context.application.bot_data["cfg"]
    if not _is_allowed(update, cfg):
        return

    await update.message.reply_text(
        "ℹ️Komendy:\n"
        "/szukaj <fraza> — szukaj\n"
        "/chatid — pokaż Chat ID\n"
        "/anuluj — przerwij bieżącą rozmowę"
    )

async def cmd_chatid(update: Update, context: ContextTypes.DEFAULT_TYPE):
    cfg: Config = context.application.bot_data["cfg"]
    if not update.effective_chat:
        return
    if cfg.allowed_chat_ids and not _is_allowed(update, cfg):
        # nawet jeśli nie jest allowed, możemy zwrócić chatid (żebyś mógł dopisać do listy)
        await update.message.reply_text(f"Chat ID: {update.effective_chat.id}")
        return
    await update.message.reply_text(f"Chat ID: {update.effective_chat.id}")

async def cmd_cancel(update: Update, context: ContextTypes.DEFAULT_TYPE):
    cfg: Config = context.application.bot_data["cfg"]
    if not _is_allowed(update, cfg):
        return ConversationHandler.END
    context.user_data.clear()
    await update.message.reply_text("OK, anulowano.", reply_markup=ReplyKeyboardRemove())
    return ConversationHandler.END

async def cmd_search(update: Update, context: ContextTypes.DEFAULT_TYPE):
    cfg: Config = context.application.bot_data["cfg"]
    if not _is_allowed(update, cfg):
        return ConversationHandler.END

    query = " ".join(context.args).strip()
    if not query:
        await update.message.reply_text("Użycie: /szukaj <fraza>")
        return ConversationHandler.END

    await update.message.reply_text("👀Szukam…")

    # search może być blokujący -> odpal w thread
    results = await asyncio.to_thread(integrations.search, query)

    if not results:
        await update.message.reply_text("⚠️Brak wyników.")
        return ConversationHandler.END

    # zapisz w pamięci (per chat/user)
    max_show = min(cfg.max_results, len(results))
    context.user_data["results"] = results[:max_show]

    lines = ["☑️Wyniki wyszukiwania (odpisz numerem):"]
    for i, r in enumerate(results[:max_show], start=1):
        lines.append(f"{i}. {r.title} [{r.size}]")

    await update.message.reply_text("\n".join(lines))
    return CHOOSE_ITEM

async def choose_item(update: Update, context: ContextTypes.DEFAULT_TYPE):
    cfg: Config = context.application.bot_data["cfg"]
    if not _is_allowed(update, cfg):
        return ConversationHandler.END

    text = (update.message.text or "").strip()
    try:
        idx = int(text)
    except ValueError:
        await update.message.reply_text("Odpisz numerem (np. 1).")
        return CHOOSE_ITEM

    results = context.user_data.get("results") or []
    if idx < 1 or idx > len(results):
        await update.message.reply_text("Nieprawidłowy numer. Spróbuj ponownie.")
        return CHOOSE_ITEM

    chosen = results[idx - 1]
    context.user_data["chosen"] = chosen

    # pokaż opcje ścieżek 1..N
    lines = ["ℹ️Wybierz gdzie zapisać (odpisz numerem):"]
    for i, (label, path) in enumerate(cfg.save_targets, start=1):
        lines.append(f"{i}. {label} → {path}")
    await update.message.reply_text("\n".join(lines), reply_markup=_targets_keyboard(cfg))
    return CHOOSE_TARGET

async def choose_target_and_download(update: Update, context: ContextTypes.DEFAULT_TYPE):
    cfg: Config = context.application.bot_data["cfg"]
    if not _is_allowed(update, cfg):
        return ConversationHandler.END

    chosen = context.user_data.get("chosen")
    if not chosen:
        await update.message.reply_text("⚠️Brak wybranego elementu. Zrób /szukaj ponownie.", reply_markup=ReplyKeyboardRemove())
        return ConversationHandler.END

    text = (update.message.text or "").strip()
    try:
        t_idx = int(text)
    except ValueError:
        await update.message.reply_text("ℹ️Odpisz numerem ścieżki (np. 1).", reply_markup=_targets_keyboard(cfg))
        return CHOOSE_TARGET

    if t_idx < 1 or t_idx > len(cfg.save_targets):
        await update.message.reply_text("⚠️Nieprawidłowy numer ścieżki!", reply_markup=_targets_keyboard(cfg))
        return CHOOSE_TARGET

    label, base_path = cfg.save_targets[t_idx - 1]
    os.makedirs(base_path, exist_ok=True)

    await update.message.reply_text(
        f"☑️Przyjąłem!"
        f"🚀Rozpoczynam pobieranie do: {label} ({base_path})\n"
        f"🍿Tytuł: {chosen.title}\n"
        f"(ℹ️Będę wysyłał statusy: KOLEJKA/POSTĘP/KONIEC)",
        reply_markup=ReplyKeyboardRemove()
    )

    chat_id = update.effective_chat.id
    loop = asyncio.get_running_loop()

    # Thread-safe notifier used by integrations.download() running in a worker thread.
    def notify_sync(msg: str) -> None:
        loop.call_soon_threadsafe(
            asyncio.create_task,
            context.bot.send_message(chat_id=chat_id, text=msg),
        )

    # SearchResult is frozen; create a copy with notify callback in payload.
    chosen_with_notify = integrations.SearchResult(
        title=chosen.title,
        size=chosen.size,
        payload={**(chosen.payload or {}), "notify": notify_sync},
    )

    async def run_job():
        try:
            final_path = await asyncio.to_thread(integrations.download, chosen_with_notify, base_path)
            await context.bot.send_message(chat_id=chat_id, text=f"✅ Zakończono: {final_path}")
        except Exception as e:
            await context.bot.send_message(chat_id=chat_id, text=f"❌ Błąd: {e!r}")

    context.application.create_task(run_job())

    context.user_data.clear()
    return ConversationHandler.END

def build_app(cfg: Config) -> Application:
    app = Application.builder().token(cfg.bot_token).build()
    app.bot_data["cfg"] = cfg

    conv = ConversationHandler(
        entry_points=[CommandHandler("szukaj", cmd_search)],
        states={
            CHOOSE_ITEM: [MessageHandler(filters.TEXT & ~filters.COMMAND, choose_item)],
            CHOOSE_TARGET: [MessageHandler(filters.TEXT & ~filters.COMMAND, choose_target_and_download)],
        },
        fallbacks=[CommandHandler("anuluj", cmd_cancel)],
        allow_reentry=True,
    )

    app.add_handler(CommandHandler("start", cmd_start))
    app.add_handler(CommandHandler("chatid", cmd_chatid))
    app.add_handler(CommandHandler("anuluj", cmd_cancel))
    app.add_handler(conv)

    return app

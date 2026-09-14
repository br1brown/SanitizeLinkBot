"""Test per TelegramHandlers: riepilogo/tastiera impostazioni e handler dei toggle.

Copre in particolare il flusso introdotto/riscritto nel commit "Impostazioni più
carine" (_build_settings_summary, cmd_settings, handle_toggle con edit_message_text
al posto di edit_message_reply_markup), che era rimasto senza test.
"""

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from telegram.constants import ChatType

from sanitizelinkbot.chat_prefs import ChatPrefs, PrefsEntry
from sanitizelinkbot.telegram_handlers import TelegramHandlers


@pytest.fixture
def handlers(monkeypatch):
    """TelegramHandlers con ChatPrefs sostituito da un fake in memoria: niente SQLite reale nei test."""
    monkeypatch.setattr(ChatPrefs, "load", classmethod(lambda cls: None))
    store: dict[int, PrefsEntry] = {}

    def fake_get(cls, chat_id):
        return store.setdefault(chat_id, PrefsEntry.from_defaults())

    async def fake_set(cls, chat_id, key, value):
        entry = fake_get(cls, chat_id)
        setattr(entry, key, value)
        return entry

    monkeypatch.setattr(ChatPrefs, "get", classmethod(fake_get))
    monkeypatch.setattr(ChatPrefs, "set", classmethod(fake_set))
    # self.sanitizer non è usato dai metodi di impostazioni testati qui
    return TelegramHandlers(sanitizer=None)


def _all_callback_data(markup):
    return [button.callback_data for row in markup.inline_keyboard for button in row]


def _update_for_settings(chat_type, chat_id=42):
    message = SimpleNamespace(reply_text=AsyncMock())
    chat = SimpleNamespace(id=chat_id, type=chat_type)
    return SimpleNamespace(effective_chat=chat, message=message), message


def _callback_update(data, chat_type=ChatType.PRIVATE, chat_id=99):
    query = SimpleNamespace(
        answer=AsyncMock(),
        data=data,
        message=SimpleNamespace(chat=SimpleNamespace(id=chat_id, type=chat_type)),
        edit_message_text=AsyncMock(),
    )
    return SimpleNamespace(callback_query=query), query


class TestFlag:
    def test_on(self, handlers):
        assert handlers._flag(True) == "🟢 ON"

    def test_off(self, handlers):
        assert handlers._flag(False) == "🔴 OFF"


class TestBuildSettingsSummary:
    def test_private_chat_has_no_group_row(self, handlers):
        prefs = PrefsEntry(
            show_title=True,
            show_url=False,
            use_privacy_frontend=True,
            group_auto=True,  # ignorato: is_group=False non deve mostrarlo
            show_preview=False,
        )
        summary = handlers._build_settings_summary(prefs, is_group=False)
        assert "URL in chiaro: 🔴 OFF" in summary
        assert "Titolo pagina: 🟢 ON" in summary
        assert "Frontend alt. [beta]: 🟢 ON" in summary
        assert "Anteprima link: 🔴 OFF" in summary
        assert "Modalità auto" not in summary

    def test_group_chat_appends_group_auto_row(self, handlers):
        prefs = PrefsEntry.from_defaults()
        summary = handlers._build_settings_summary(prefs, is_group=True)
        assert "Modalità auto: 🔴 OFF" in summary  # from_defaults(): group_auto=False
        # 5 righe unite da "\n\n" -> 4 separatori
        assert summary.count("\n\n") == 4


class TestBuildSettingsKeyboard:
    def test_private_keyboard_has_no_group_auto_button(self, handlers):
        markup = handlers._build_settings_keyboard(PrefsEntry.from_defaults(), is_group=False)
        assert _all_callback_data(markup) == [
            "toggle:show_url",
            "toggle:show_title",
            "toggle:use_privacy_frontend",
            "toggle:show_preview",
            "toggle:close",
        ]

    def test_group_keyboard_includes_group_auto_before_close(self, handlers):
        markup = handlers._build_settings_keyboard(PrefsEntry.from_defaults(), is_group=True)
        assert _all_callback_data(markup)[-2:] == ["toggle:group_auto", "toggle:close"]


class TestCmdSettings:
    async def test_private_chat_renders_settings_private_template(self, handlers):
        update, message = _update_for_settings(ChatType.PRIVATE)
        await handlers.cmd_settings(update, context=None)

        message.reply_text.assert_awaited_once()
        text = message.reply_text.await_args.args[0]
        assert "solo per questa chat" in text
        assert "URL in chiaro: 🟢 ON" in text
        markup = message.reply_text.await_args.kwargs["reply_markup"]
        assert markup.inline_keyboard[-1][0].callback_data == "toggle:close"
        assert "toggle:group_auto" not in _all_callback_data(markup)

    async def test_group_chat_renders_settings_group_template_with_auto_row(self, handlers):
        update, message = _update_for_settings(ChatType.SUPERGROUP)
        await handlers.cmd_settings(update, context=None)

        text = message.reply_text.await_args.args[0]
        assert "solo per questo gruppo" in text
        assert "Modalità auto: 🔴 OFF" in text  # from_defaults(): group_auto=False


class TestHandleToggle:
    async def test_close_edits_message_without_keyboard(self, handlers):
        update, query = _callback_update("toggle:close")
        await handlers.handle_toggle(update, context=None)

        query.answer.assert_awaited_once_with()
        query.edit_message_text.assert_awaited_once()
        text = query.edit_message_text.await_args.args[0]
        assert "Impostazioni aggiornate" in text
        assert query.edit_message_text.await_args.kwargs["reply_markup"] is None

    async def test_toggle_pref_flips_value_and_redraws(self, handlers):
        update, query = _callback_update("toggle:show_url", chat_id=100)
        assert ChatPrefs.get(100).show_url is True

        await handlers.handle_toggle(update, context=None)

        assert ChatPrefs.get(100).show_url is False
        text = query.edit_message_text.await_args.args[0]
        assert "URL in chiaro: 🔴 OFF" in text
        markup = query.edit_message_text.await_args.kwargs["reply_markup"]
        assert "toggle:show_url" in _all_callback_data(markup)

    async def test_group_chat_toggle_keeps_group_auto_row(self, handlers):
        update, query = _callback_update(
            "toggle:show_title", chat_type=ChatType.GROUP, chat_id=101
        )
        await handlers.handle_toggle(update, context=None)

        markup = query.edit_message_text.await_args.kwargs["reply_markup"]
        assert "toggle:group_auto" in _all_callback_data(markup)

    async def test_unknown_toggle_key_is_ignored(self, handlers):
        update, query = _callback_update("toggle:not_a_real_key", chat_id=102)
        await handlers.handle_toggle(update, context=None)
        query.edit_message_text.assert_not_awaited()

    async def test_non_toggle_data_is_ignored(self, handlers):
        update, query = _callback_update("something-else", chat_id=103)
        await handlers.handle_toggle(update, context=None)
        query.edit_message_text.assert_not_awaited()

    async def test_error_while_toggling_answers_with_alert(self, handlers, monkeypatch):
        async def boom(cls, chat_id, key, value):
            raise RuntimeError("db down")

        monkeypatch.setattr(ChatPrefs, "set", classmethod(boom))
        update, query = _callback_update("toggle:show_url", chat_id=104)

        await handlers.handle_toggle(update, context=None)

        # 1a chiamata: ack immediato a inizio handler. 2a: notifica di errore col show_alert.
        assert query.answer.await_count == 2
        _, kwargs = query.answer.await_args
        assert kwargs.get("show_alert") is True

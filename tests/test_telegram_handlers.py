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
        # 6 righe unite da "\n\n" -> 5 separatori
        assert summary.count("\n\n") == 5


class TestBuildSettingsKeyboard:
    def test_private_keyboard_has_no_group_auto_button(self, handlers):
        markup = handlers._build_settings_keyboard(PrefsEntry.from_defaults(), is_group=False)
        assert _all_callback_data(markup) == [
            "toggle:show_url",
            "toggle:show_title",
            "toggle:use_privacy_frontend",
            "toggle:show_preview",
            "toggle:scan_enabled",
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


# --- /scan (ScanMalware) --------------------------------------------------------


def _scan_summary(verdict):
    return {
        "scan_id": "abc-123",
        "url": "https://example.com",
        "final_url": "https://example.com/",
        "status": "completed",
        "security_verdict": verdict,
        "risk_score": 95 if verdict else 0,
        "redirect_count": 2,
        "tracker_count": 1,
        "certificate_valid": False,
    }


class _FakeScanClient:
    def __init__(self, summary, screenshot=b"png", scan_id="abc-123"):
        self.summary = summary
        self.screenshot = screenshot
        self.scan_id = scan_id
        self.submitted = []

    @staticmethod
    def report_url(scan_id):
        return f"https://scanmalware.com/result/{scan_id}"

    async def submit_scan(self, url):
        self.submitted.append(url)
        return self.scan_id

    async def wait_for_result(self, scan_id):
        return self.summary

    async def fetch_screenshot(self, scan_id):
        return self.screenshot


def _scan_update(args=None, reply_to_message=None):
    notice = SimpleNamespace(edit_text=AsyncMock(), delete=AsyncMock())
    message = SimpleNamespace(
        reply_text=AsyncMock(return_value=notice),
        reply_photo=AsyncMock(),
        reply_to_message=reply_to_message,
    )
    update = SimpleNamespace(
        effective_message=message, effective_chat=SimpleNamespace(id=SCAN_CHAT_ID)
    )
    context = SimpleNamespace(args=args or [])
    return update, context, message, notice


SCAN_CHAT_ID = 777


@pytest.fixture
def scan_enabled(handlers):
    """Abilita la preferenza scan_enabled sulla chat usata dai test di /scan (default: OFF)."""
    ChatPrefs.get(SCAN_CHAT_ID).scan_enabled = True


def _handlers_with_scan_client(handlers, client):
    handlers.sanitizer = SimpleNamespace(scanmalware=client)
    return handlers


class TestFormatScanReport:
    def test_malicious_lists_score_factors_and_report_link(self):
        summary = _scan_summary(
            {
                "verdict": "Malicious",
                "risk_level": "malicious",
                "overall_score": 95,
                "risk_factors": ["IoC on domain <x>", "flagged external domain"],
            }
        )
        text = TelegramHandlers._format_scan_report(summary, "https://scanmalware.com/result/abc-123")
        assert text.startswith("🔴 <b>Malevolo</b>")
        assert "Malicious — punteggio di rischio 95/100" in text
        assert "<code>https://example.com/</code>" in text
        assert "Redirect: 2, tracker: 1, certificato tls non valido" in text
        assert "• IoC on domain &lt;x&gt;" in text  # escape HTML dei fattori
        assert '<a href="https://scanmalware.com/result/abc-123">Report completo →</a>' in text

    def test_low_risk(self):
        summary = _scan_summary({"verdict": "Low Risk", "risk_level": "low", "overall_score": 23})
        text = TelegramHandlers._format_scan_report(summary, "https://r")
        assert text.startswith("✅ <b>Nessuna minaccia rilevata</b>")
        assert "Low Risk — punteggio di rischio 23/100" in text

    def test_pending_verdict(self):
        text = TelegramHandlers._format_scan_report(_scan_summary({}), "https://r")
        assert text.startswith("⏳ <b>Verdetto non ancora disponibile</b>")
        assert "ancora in corso" in text
        assert "punteggio" not in text


class TestCmdScan:
    async def test_disabled_by_default_points_to_settings(self, handlers):
        client = _FakeScanClient(_scan_summary({"risk_level": "low", "verdict": "Low Risk"}))
        _handlers_with_scan_client(handlers, client)
        update, context, message, _ = _scan_update(args=["https://private.example/invite"])

        await handlers.cmd_scan(update, context)

        assert client.submitted == []  # nulla inviato al servizio esterno
        text = message.reply_text.await_args.args[0]
        assert "disattivato" in text and "/settings" in text
        message.reply_photo.assert_not_awaited()

    async def test_without_url_explains_usage(self, handlers, scan_enabled):
        update, context, message, _ = _scan_update(args=[])
        await handlers.cmd_scan(update, context)
        message.reply_text.assert_awaited_once()
        assert "/scan" in message.reply_text.await_args.args[0]

    async def test_sends_screenshot_with_verdict_caption_and_deletes_notice(self, handlers, scan_enabled):
        client = _FakeScanClient(_scan_summary({"verdict": "Malicious", "risk_level": "malicious", "overall_score": 95}))
        _handlers_with_scan_client(handlers, client)
        update, context, message, notice = _scan_update(args=["https://example.com/?x=1"])

        await handlers.cmd_scan(update, context)

        assert client.submitted == ["https://example.com/?x=1"]
        # Avviso iniziale: servizio esterno, report visibile a chi ha il link
        first_text = message.reply_text.await_args_list[0].args[0]
        assert "ScanMalware" in first_text and "link" in first_text
        assert "pubblic" not in first_text.lower()
        message.reply_photo.assert_awaited_once()
        kwargs = message.reply_photo.await_args.kwargs
        assert kwargs["photo"] == b"png"
        assert kwargs["has_spoiler"] is True
        assert kwargs["caption"].startswith("🔴 <b>Malevolo</b>")
        assert "scanmalware.com/result/abc-123" in kwargs["caption"]
        notice.delete.assert_awaited_once()
        notice.edit_text.assert_not_awaited()

    async def test_url_taken_from_replied_message(self, handlers, scan_enabled, monkeypatch):
        from sanitizelinkbot.telegram_handlers import GetterUrl

        monkeypatch.setattr(GetterUrl, "urls_from_message", staticmethod(lambda m: ["https://quoted.example/"]))
        client = _FakeScanClient(_scan_summary({"risk_level": "low", "verdict": "Low Risk"}))
        _handlers_with_scan_client(handlers, client)
        update, context, message, _ = _scan_update(args=[], reply_to_message=SimpleNamespace())

        await handlers.cmd_scan(update, context)

        assert client.submitted == ["https://quoted.example/"]

    async def test_without_screenshot_edits_notice_with_text(self, handlers, scan_enabled):
        client = _FakeScanClient(_scan_summary({"risk_level": "low", "verdict": "Low Risk"}), screenshot=None)
        _handlers_with_scan_client(handlers, client)
        update, context, message, notice = _scan_update(args=["https://example.com"])

        await handlers.cmd_scan(update, context)

        message.reply_photo.assert_not_awaited()
        notice.edit_text.assert_awaited_once()
        assert notice.edit_text.await_args.args[0].startswith("✅")

    async def test_photo_failure_falls_back_to_text(self, handlers, scan_enabled):
        client = _FakeScanClient(_scan_summary({"risk_level": "low", "verdict": "Low Risk"}))
        _handlers_with_scan_client(handlers, client)
        update, context, message, notice = _scan_update(args=["https://example.com"])
        message.reply_photo.side_effect = RuntimeError("telegram down")

        await handlers.cmd_scan(update, context)

        notice.edit_text.assert_awaited_once()
        notice.delete.assert_not_awaited()

    async def test_submit_failure(self, handlers, scan_enabled):
        client = _FakeScanClient(_scan_summary({}), scan_id=None)
        _handlers_with_scan_client(handlers, client)
        update, context, message, notice = _scan_update(args=["https://example.com"])

        await handlers.cmd_scan(update, context)

        assert "Impossibile avviare" in notice.edit_text.await_args.args[0]
        message.reply_photo.assert_not_awaited()

    async def test_scan_failed_or_timed_out_links_report(self, handlers, scan_enabled):
        client = _FakeScanClient(None)
        _handlers_with_scan_client(handlers, client)
        update, context, message, notice = _scan_update(args=["https://example.com"])

        await handlers.cmd_scan(update, context)

        text = notice.edit_text.await_args.args[0]
        assert "scanmalware.com/result/abc-123" in text

"""tests/test_mail_calendar_providers.py - Comprehensive tests for Google Workspace and Microsoft 365 OAuth2 integrations."""

import os
import sys
import json
import base64
import unittest
from unittest.mock import MagicMock, patch

import homie_mail_calendar
from homie_mail_calendar import (
    MailConnector,
    CalendarConnector,
    get_mail_connector,
    get_calendar_connector,
    fetch_unread_emails,
    fetch_outlook_emails,
    fetch_calendar_events,
    send_email,
    load_settings,
    get_mail_provider,
    save_google_token,
    save_ms_token,
    get_google_token_path,
    get_ms_token_path,
    GMAIL_SCOPES,
    MSAL_SCOPES,
)


class TestMailCalendarProviders(unittest.TestCase):

    def setUp(self):
        self.tmp_dir = os.path.join(os.path.dirname(__file__), ".test_tmp")
        os.makedirs(self.tmp_dir, exist_ok=True)

    def tearDown(self):
        # Clean up environment variables if set during test
        for var in ["HOMIE_MAIL_PROVIDER", "HOMIE_GOOGLE_TOKEN_PATH", "HOMIE_MS_TOKEN_PATH", "HOMIE_MS_TOKEN"]:
            os.environ.pop(var, None)

    # ------------------------------------------------------------------------
    # 1. Provider Detection & Settings
    # ------------------------------------------------------------------------

    def test_provider_detection_defaults_to_mock(self):
        """Verifies default provider is 'mock' and existing tests remain unaffected."""
        provider = get_mail_provider()
        self.assertIn(provider, ["mock", "gmail", "outlook"])
        conn = MailConnector()
        self.assertEqual(conn.provider, "mock")

    def test_provider_detection_env_override(self):
        """Verifies environment variable HOMIE_MAIL_PROVIDER overrides settings."""
        os.environ["HOMIE_MAIL_PROVIDER"] = "gmail"
        conn = MailConnector()
        self.assertEqual(conn.provider, "gmail")

        os.environ["HOMIE_MAIL_PROVIDER"] = "outlook"
        conn2 = MailConnector()
        self.assertEqual(conn2.provider, "outlook")

    def test_explicit_provider_injection(self):
        """Verifies provider can be specified explicitly on constructor."""
        conn_gmail = MailConnector(provider="gmail")
        self.assertEqual(conn_gmail.provider, "gmail")

        conn_outlook = MailConnector(provider="outlook")
        self.assertEqual(conn_outlook.provider, "outlook")

        conn_mock = MailConnector(provider="mock")
        self.assertEqual(conn_mock.provider, "mock")

    # ------------------------------------------------------------------------
    # 2. Gmail Integration
    # ------------------------------------------------------------------------

    def test_gmail_token_saving_and_scopes(self):
        """Verifies Gmail token persistence and scope requirements."""
        token_path = os.path.join(self.tmp_dir, "test_google_token.json")
        test_creds = {
            "token": "ya29.sample_access_token",
            "refresh_token": "1//sample_refresh_token",
            "token_uri": "https://oauth2.googleapis.com/token",
            "client_id": "test_client_id.apps.googleusercontent.com",
            "client_secret": "test_client_secret",
            "scopes": GMAIL_SCOPES
        }
        saved_path = save_google_token(test_creds, path=token_path)
        self.assertTrue(os.path.exists(saved_path))
        with open(saved_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["token"], "ya29.sample_access_token")
        self.assertTrue(any("gmail.readonly" in s for s in GMAIL_SCOPES))
        self.assertTrue(any("gmail.send" in s for s in GMAIL_SCOPES))
        self.assertTrue(any("gmail.modify" in s for s in GMAIL_SCOPES))

    def test_gmail_fetch_unread_emails(self):
        """Verifies fetch_unread_emails queries Gmail API with q='is:unread' and parses messages."""
        mock_service = MagicMock()
        mock_messages_resource = MagicMock()
        mock_service.users().messages.return_value = mock_messages_resource

        # Mock list response
        mock_messages_resource.list.return_value.execute.return_value = {
            "messages": [{"id": "msg_gmail_101", "threadId": "th_gmail_101"}]
        }

        # Mock get response with MIME payload
        sample_body_text = "Important Security Notice from IT"
        encoded_body = base64.urlsafe_b64encode(sample_body_text.encode("utf-8")).decode("ascii")
        mock_messages_resource.get.return_value.execute.return_value = {
            "id": "msg_gmail_101",
            "threadId": "th_gmail_101",
            "snippet": "Important Security Notice",
            "payload": {
                "headers": [
                    {"name": "Subject", "value": "Security Bulletin Q4"},
                    {"name": "From", "value": "Security Team <sec@corp.com>"},
                    {"name": "To", "value": "alice@corp.com, bob@corp.com"},
                    {"name": "Date", "value": "Wed, 18 Nov 2026 12:00:00 +0000"}
                ],
                "parts": [
                    {
                        "mimeType": "text/plain",
                        "body": {"data": encoded_body}
                    }
                ]
            }
        }

        conn = MailConnector(provider="gmail", gmail_service=mock_service)
        unread = conn.fetch_unread_emails(max_results=5)

        # Assert query executed with q='is:unread'
        mock_messages_resource.list.assert_called_with(userId="me", q="is:unread", maxResults=5)
        self.assertEqual(len(unread), 1)
        item = unread[0]
        self.assertEqual(item["id"], "msg_gmail_101")
        self.assertEqual(item["subject"], "Security Bulletin Q4")
        self.assertEqual(item["from"], "Security Team <sec@corp.com>")
        self.assertIn("alice@corp.com", item["to"])
        self.assertIn(sample_body_text, item["body"])

    def test_gmail_send_email(self):
        """Verifies send_email creates base64 RFC 2822 message and calls Gmail API send endpoint."""
        mock_service = MagicMock()
        mock_messages_resource = MagicMock()
        mock_service.users().messages.return_value = mock_messages_resource
        mock_messages_resource.send.return_value.execute.return_value = {
            "id": "sent_msg_202",
            "threadId": "th_sent_202"
        }

        conn = MailConnector(provider="gmail", gmail_service=mock_service)
        res = conn.send_email(to="colleague@corp.com", subject="Test Gmail Send", body="Hello from Gmail API!")

        self.assertEqual(res["id"], "sent_msg_202")
        mock_messages_resource.send.assert_called_once()
        call_kwargs = mock_messages_resource.send.call_args[1]
        self.assertEqual(call_kwargs["userId"], "me")
        raw_b64 = call_kwargs["body"]["raw"]
        raw_decoded = base64.urlsafe_b64decode(raw_b64.encode("ascii")).decode("utf-8")
        self.assertIn("To: colleague@corp.com", raw_decoded)
        self.assertIn("Subject: Test Gmail Send", raw_decoded)
        self.assertIn("Hello from Gmail API!", raw_decoded)

    # ------------------------------------------------------------------------
    # 3. Microsoft Graph (Outlook) Integration
    # ------------------------------------------------------------------------

    def test_msal_scopes_and_token_saving(self):
        """Verifies MSAL scopes and token saving functionality."""
        token_path = os.path.join(self.tmp_dir, "test_ms_token.json")
        saved_path = save_ms_token({"access_token": "ms_graph_sample_jwt"}, path=token_path)
        self.assertTrue(os.path.exists(saved_path))
        with open(saved_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.assertEqual(data["access_token"], "ms_graph_sample_jwt")
        self.assertIn("Mail.Read", MSAL_SCOPES)
        self.assertIn("Mail.Send", MSAL_SCOPES)
        self.assertIn("Calendars.Read", MSAL_SCOPES)

    @patch("homie_mail_calendar.requests.get")
    def test_outlook_fetch_unread_emails(self, mock_get):
        """Verifies fetch_outlook_emails calls Graph messages endpoint with isRead eq false."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "value": [
                {
                    "id": "ms_msg_001",
                    "conversationId": "ms_conv_001",
                    "subject": "Microsoft 365 Architecture Update",
                    "from": {"emailAddress": {"name": "Satya", "address": "satya@corp.com"}},
                    "toRecipients": [{"emailAddress": {"address": "rush@corp.com"}}],
                    "receivedDateTime": "2026-11-18T10:30:00Z",
                    "body": {"content": "Here is the Outlook sync specification."},
                    "bodyPreview": "Here is the Outlook...",
                    "isRead": False
                }
            ]
        }
        mock_get.return_value = mock_resp

        conn = MailConnector(provider="outlook", ms_token="test_bearer_token")
        emails = conn.fetch_outlook_emails(max_results=10)

        self.assertEqual(len(emails), 1)
        em = emails[0]
        self.assertEqual(em["id"], "ms_msg_001")
        self.assertEqual(em["subject"], "Microsoft 365 Architecture Update")
        self.assertIn("satya@corp.com", em["from"])
        self.assertIn("rush@corp.com", em["to"])
        self.assertIn("Outlook sync specification", em["body"])

        # Check request URL contains $filter=isRead eq false
        mock_get.assert_called_once()
        called_url = mock_get.call_args[0][0]
        self.assertIn("https://graph.microsoft.com/v1.0/me/messages", called_url)
        self.assertIn("$filter=isRead eq false", called_url)

    @patch("homie_mail_calendar.requests.get")
    def test_outlook_fetch_calendar_events(self, mock_get):
        """Verifies fetch_calendar_events queries Microsoft Graph calendarView endpoint."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "value": [
                {
                    "id": "ev_ms_999",
                    "subject": "Q4 Strategy Workshop",
                    "start": {"dateTime": "2026-11-20T14:00:00.0000000"},
                    "end": {"dateTime": "2026-11-20T16:00:00.0000000"},
                    "location": {"displayName": "Executive Boardroom"},
                    "body": {"content": "Discussing 2027 enterprise roadmaps."},
                    "attendees": [{"emailAddress": {"address": "exec@corp.com"}}],
                    "responseStatus": {"response": "accepted"}
                }
            ]
        }
        mock_get.return_value = mock_resp

        cal = CalendarConnector(provider="outlook", ms_token="test_cal_bearer_token")
        events = cal.fetch_calendar_events(days_ahead=7)

        self.assertEqual(len(events), 1)
        ev = events[0]
        self.assertEqual(ev["event_id"], "ev_ms_999")
        self.assertEqual(ev["title"], "Q4 Strategy Workshop")
        self.assertEqual(ev["location"], "Executive Boardroom")
        self.assertIn("exec@corp.com", ev["attendees"])

        # Verify URL called calendarView
        mock_get.assert_called_once()
        called_url = mock_get.call_args[0][0]
        self.assertIn("https://graph.microsoft.com/v1.0/me/calendarView", called_url)
        self.assertIn("startDateTime=", called_url)
        self.assertIn("endDateTime=", called_url)

    @patch("homie_mail_calendar.requests.post")
    def test_outlook_send_email(self, mock_post):
        """Verifies send_email dispatches via Microsoft Graph sendMail endpoint."""
        mock_resp = MagicMock()
        mock_resp.status_code = 202
        mock_resp.raise_for_status = MagicMock()
        mock_post.return_value = mock_resp

        conn = MailConnector(provider="outlook", ms_token="test_bearer_token")
        res = conn.send_email(to="partner@external.org", subject="Outlook Project Review", body="Review document text.")

        self.assertEqual(res["status"], "SENT")
        self.assertEqual(res["provider"], "outlook")

        mock_post.assert_called_once()
        called_url = mock_post.call_args[0][0]
        self.assertEqual(called_url, "https://graph.microsoft.com/v1.0/me/sendMail")
        called_json = mock_post.call_args[1]["json"]
        self.assertEqual(called_json["message"]["subject"], "Outlook Project Review")
        self.assertEqual(called_json["message"]["body"]["content"], "Review document text.")
        self.assertEqual(called_json["message"]["toRecipients"][0]["emailAddress"]["address"], "partner@external.org")

    # ------------------------------------------------------------------------
    # 4. Provider-Agnostic Routing & Mock Mode Fallback
    # ------------------------------------------------------------------------

    def test_mock_provider_unread_and_send(self):
        """Verifies mock mode functions correctly when mail_provider is mock."""
        conn = MailConnector(provider="mock")
        conn.add_mock_thread(
            thread_id="mock_th_1",
            subject="Local Mock Subject",
            messages=[
                {
                    "from": "alice@local.dev",
                    "to": ["bob@local.dev"],
                    "body": "Mock body content.",
                    "is_read": False
                }
            ]
        )

        # Provider agnostic fetch_unread_emails returns mock messages
        unread = conn.fetch_unread_emails(max_results=5)
        self.assertEqual(len(unread), 1)
        self.assertEqual(unread[0]["subject"], "Local Mock Subject")
        self.assertEqual(unread[0]["from"], "alice@local.dev")

        # Provider agnostic send_email saves to mock store
        send_res = conn.send_email(to="charlie@local.dev", subject="Mock Sent", body="Test body")
        self.assertEqual(send_res["status"], "SENT")
        self.assertIn(send_res["id"], conn._sent_messages)

    def test_calendar_mock_fetch_events(self):
        """Verifies CalendarConnector mock mode returns local events."""
        from homie_mail_calendar import CalendarEvent
        import time

        cal = CalendarConnector(provider="mock")
        now = time.time()
        cal.add_event(CalendarEvent(
            event_id="cal_mock_01",
            title="Local Mock Sync",
            start_ts=now + 1000,
            end_ts=now + 2000,
            location="Room A",
            description="Discussion"
        ))

        events = cal.fetch_calendar_events(days_ahead=2)
        self.assertEqual(len(events), 1)
        self.assertEqual(events[0]["title"], "Local Mock Sync")

    def test_module_level_helpers(self):
        """Verifies module-level convenience functions route to global connectors."""
        conn = get_mail_connector()
        conn.add_mock_thread(
            thread_id="th_global_01",
            subject="Global Helper Test",
            messages=[{"from": "dev@corp.com", "to": ["user@corp.com"], "body": "Body", "is_read": False}]
        )

        unread = fetch_unread_emails(max_results=5)
        self.assertGreaterEqual(len(unread), 1)

        sent = send_email(to="test@corp.com", subject="Test Subj", body="Test Body")
        self.assertEqual(sent["status"], "SENT")


if __name__ == "__main__":
    unittest.main()

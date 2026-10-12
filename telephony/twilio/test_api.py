import frappe
from frappe.tests import IntegrationTestCase
from frappe.utils import set_request
from frappe.utils.password import set_encrypted_password
from twilio.request_validator import RequestValidator

from telephony.twilio.api import twilio_incoming_call_handler, validate_twilio_request
from telephony.twilio.utils import get_public_url

AUTH_TOKEN = "test-auth-token"
PATH = "/api/method/telephony.twilio.api.twilio_incoming_call_handler"
FORM = {"CallSid": "CAtestsignature", "From": "+15550000000", "To": "+15550000001"}


class TestTwilioWebhookSignature(IntegrationTestCase):
    def setUp(self):
        frappe.db.set_single_value("TP Twilio Settings", "enabled", 1)
        set_encrypted_password(
            "TP Twilio Settings", "TP Twilio Settings", AUTH_TOKEN, "auth_token"
        )

    def test_accepts_signed_request(self):
        self.make_request(sign_with=AUTH_TOKEN)
        validate_twilio_request()

    def test_rejects_unsigned_forged_or_tampered_request(self):
        for token, data in [
            (None, FORM),
            ("wrong-token", FORM),
            (AUTH_TOKEN, {**FORM, "From": "+15559999999"}),
        ]:
            self.make_request(sign_with=token, data=data)
            with self.assertRaises(frappe.PermissionError):
                twilio_incoming_call_handler(**data)
        self.assertFalse(frappe.db.exists("TP Call Log", FORM["CallSid"]))

    def test_rejects_when_twilio_is_disabled(self):
        frappe.db.set_single_value("TP Twilio Settings", "enabled", 0)
        self.make_request(sign_with=AUTH_TOKEN)
        with self.assertRaises(frappe.PermissionError):
            validate_twilio_request()

    def make_request(self, sign_with=None, data=FORM):
        """Sets a POST request whose signature always covers FORM, not `data`."""
        set_request(method="POST", path=PATH, data=data)
        if not sign_with:
            return
        # The public URL depends on the request host, so sign after setting it.
        signature = RequestValidator(sign_with).compute_signature(
            get_public_url(PATH), FORM
        )
        headers = {"X-Twilio-Signature": signature}
        set_request(method="POST", path=PATH, data=data, headers=headers)

"""
JPG Law — Attorney Review Checkout Service

Receives redirects from Pacta Handbook, renders the engagement letter,
collects payment via Stripe under JPG Law's Stripe account, then
notifies Pacta once the payment clears.

Routes
------
  GET  /engage?token=<signed>  Render engagement letter + Pay button
  POST /checkout               Create Stripe Checkout session, redirect
  POST /webhook                Stripe webhook → mark paid → notify Pacta
  GET  /success                Post-payment thank-you page
  GET  /cancel                 Cancelled / back to handbook

Env vars
--------
  JPG_STRIPE_SECRET_KEY      JPG Law Stripe secret key  (sk_live_... / sk_test_...)
  JPG_STRIPE_WEBHOOK_SECRET  Stripe webhook signing secret  (whsec_...)
  JPG_STRIPE_TEST_BYPASS     "true" to skip Stripe in QA
  PACTA_CHECKOUT_SECRET      Shared HMAC key with Pacta (for token verification)
  PACTA_CALLBACK_SECRET      Shared HMAC key for server-to-server payment notification
  PACTA_BASE_URL             https://compliance.pactalegal.ai
  BASE_URL                   https://checkout.jpg-law.net
  SECRET_KEY                 Flask session signing key (any random string)
"""
from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import json
import os
import secrets
import urllib.error
import urllib.parse
import urllib.request

from flask import Flask, abort, redirect, render_template, request, url_for

# ── Config ───────────────────────────────────────────────────────────────────

JPG_STRIPE_SECRET_KEY     = os.environ.get("JPG_STRIPE_SECRET_KEY", "")
JPG_STRIPE_WEBHOOK_SECRET = os.environ.get("JPG_STRIPE_WEBHOOK_SECRET", "")
JPG_STRIPE_TEST_BYPASS    = os.environ.get("JPG_STRIPE_TEST_BYPASS", "").lower() == "true"
PACTA_CHECKOUT_SECRET     = os.environ.get("PACTA_CHECKOUT_SECRET", "")
PACTA_CALLBACK_SECRET     = os.environ.get("PACTA_CALLBACK_SECRET", "")
PACTA_BASE_URL            = os.environ.get("PACTA_BASE_URL", "https://compliance.pactalegal.ai").rstrip("/")
BASE_URL                  = os.environ.get("BASE_URL", "https://checkout.jpg-law.net").rstrip("/")
TOKEN_TTL_SECONDS         = 3600  # tokens expire after 1 hour

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", secrets.token_hex(32))

# ── Token helpers ─────────────────────────────────────────────────────────────

def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_decode(s: str) -> bytes:
    pad = 4 - len(s) % 4
    return base64.urlsafe_b64decode(s + "=" * (pad % 4))


def _sign(payload: str, secret: str) -> str:
    """HMAC-SHA256 signature over payload string."""
    return hmac.new(secret.encode(), payload.encode(), hashlib.sha256).hexdigest()


def create_token(data: dict, secret: str) -> str:
    """
    Encode data as a signed URL-safe token.
    Format: base64url(json_payload).signature
    """
    data["exp"] = int(datetime.datetime.utcnow().timestamp()) + TOKEN_TTL_SECONDS
    payload = _b64url_encode(json.dumps(data, separators=(",", ":")).encode())
    sig     = _sign(payload, secret)
    return f"{payload}.{sig}"


def verify_token(token: str, secret: str) -> dict | None:
    """
    Verify and decode a signed token.  Returns payload dict or None if invalid/expired.
    """
    if not secret:
        return None
    try:
        payload, sig = token.rsplit(".", 1)
    except ValueError:
        return None

    expected = _sign(payload, secret)
    if not hmac.compare_digest(expected, sig):
        return None

    try:
        data = json.loads(_b64url_decode(payload))
    except Exception:
        return None

    if data.get("exp", 0) < datetime.datetime.utcnow().timestamp():
        return None

    return data


# ── Stripe helpers ────────────────────────────────────────────────────────────

def _stripe_request(method: str, path: str, body: dict | None = None) -> dict:
    url  = f"https://api.stripe.com{path}"
    data = urllib.parse.urlencode(body).encode() if body else None
    req  = urllib.request.Request(url, data=data, method=method)
    req.add_header("Authorization", f"Bearer {JPG_STRIPE_SECRET_KEY}")
    if data:
        req.add_header("Content-Type", "application/x-www-form-urlencoded")
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read())


# ── Pacta notification ────────────────────────────────────────────────────────

def _notify_pacta(review_id: str, amount_cents: int, payment_id: str) -> bool:
    """
    POST to Pacta to mark an attorney review as paid.
    Signs the payload with PACTA_CALLBACK_SECRET so Pacta can verify it.
    """
    if not PACTA_CALLBACK_SECRET:
        print(f"[CHECKOUT] PACTA_CALLBACK_SECRET not set — skipping Pacta notification "
              f"for review_id={review_id}", flush=True)
        return False

    payload = json.dumps({
        "review_id":    review_id,
        "amount_cents": amount_cents,
        "payment_id":   payment_id,
    }, separators=(",", ":"))

    sig = hmac.new(
        PACTA_CALLBACK_SECRET.encode(),
        payload.encode(),
        hashlib.sha256,
    ).hexdigest()

    url = f"{PACTA_BASE_URL}/api/billing/jpglaw-payment"
    req = urllib.request.Request(
        url,
        data=payload.encode(),
        method="POST",
    )
    req.add_header("Content-Type", "application/json")
    req.add_header("X-JPGLaw-Sig", sig)

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read())
            print(f"[CHECKOUT] Pacta notified for review_id={review_id}: {result}", flush=True)
            return True
    except Exception as exc:
        print(f"[CHECKOUT] Pacta notification failed for review_id={review_id}: {exc}", flush=True)
        return False


# ── Pricing display helpers ───────────────────────────────────────────────────

_COMPLEX_STATES = {"CA", "NY", "IL", "MA", "WA", "CO", "NJ", "DC", "MN"}

_STATE_NAMES = {
    "AL": "Alabama", "AK": "Alaska", "AZ": "Arizona", "AR": "Arkansas",
    "CA": "California", "CO": "Colorado", "CT": "Connecticut", "DC": "Washington, D.C.",
    "DE": "Delaware", "FL": "Florida", "GA": "Georgia", "HI": "Hawaii",
    "ID": "Idaho", "IL": "Illinois", "IN": "Indiana", "IA": "Iowa",
    "KS": "Kansas", "KY": "Kentucky", "LA": "Louisiana", "ME": "Maine",
    "MD": "Maryland", "MA": "Massachusetts", "MI": "Michigan", "MN": "Minnesota",
    "MS": "Mississippi", "MO": "Missouri", "MT": "Montana", "NE": "Nebraska",
    "NV": "Nevada", "NH": "New Hampshire", "NJ": "New Jersey", "NM": "New Mexico",
    "NY": "New York", "NC": "North Carolina", "ND": "North Dakota", "OH": "Ohio",
    "OK": "Oklahoma", "OR": "Oregon", "PA": "Pennsylvania", "RI": "Rhode Island",
    "SC": "South Carolina", "SD": "South Dakota", "TN": "Tennessee", "TX": "Texas",
    "UT": "Utah", "VT": "Vermont", "VA": "Virginia", "WA": "Washington",
    "WV": "West Virginia", "WI": "Wisconsin", "WY": "Wyoming",
}


def _state_label(code: str) -> str:
    return _STATE_NAMES.get(code.upper(), code)


# ── Routes ───────────────────────────────────────────────────────────────────

@app.route("/health")
def health():
    return {"ok": True}


@app.route("/engage")
def engage():
    """
    Decode the signed token from Pacta and render the engagement letter.
    """
    raw_token = request.args.get("token", "")
    if not raw_token:
        abort(400, "Missing token")

    if not PACTA_CHECKOUT_SECRET:
        # Dev mode — accept any token without verification
        try:
            payload = raw_token.split(".")[0]
            data    = json.loads(_b64url_decode(payload))
        except Exception:
            abort(400, "Malformed token")
    else:
        data = verify_token(raw_token, PACTA_CHECKOUT_SECRET)
        if not data:
            abort(400, "Invalid or expired token. Please return to Pacta and try again.")

    states       = data.get("states", [])
    amount_cents = data.get("amount_cents", 0)
    amount_dol   = f"${amount_cents / 100:,.2f}"
    company_name = data.get("company_name", "Your Company")
    user_name    = data.get("user_name", "")
    user_email   = data.get("user_email", "")
    review_id    = data.get("review_id", "")
    profile_id   = data.get("profile_id", "")
    draft_id     = data.get("draft_id", "")

    # Build state breakdown for display
    complex_states  = [s for s in states if s.upper() in _COMPLEX_STATES]
    standard_states = [s for s in states if s.upper() not in _COMPLEX_STATES]

    today = datetime.date.today().strftime("%B %d, %Y")

    return render_template(
        "engage.html",
        raw_token       = raw_token,
        company_name    = company_name,
        user_name       = user_name,
        user_email      = user_email,
        review_id       = review_id,
        profile_id      = profile_id,
        draft_id        = draft_id,
        states          = states,
        complex_states  = complex_states,
        standard_states = standard_states,
        amount_cents    = amount_cents,
        amount_dol      = amount_dol,
        today           = today,
        state_label     = _state_label,
        bypass          = JPG_STRIPE_TEST_BYPASS or not JPG_STRIPE_SECRET_KEY,
    )


@app.route("/checkout", methods=["POST"])
def checkout():
    """
    Create a Stripe Checkout session and redirect the user there.
    """
    raw_token    = request.form.get("token", "")
    review_id    = request.form.get("review_id", "")
    profile_id   = request.form.get("profile_id", "")
    draft_id     = request.form.get("draft_id", "")
    amount_cents = int(request.form.get("amount_cents", "0"))
    company_name = request.form.get("company_name", "")
    user_email   = request.form.get("user_email", "")
    states_raw   = request.form.get("states", "")
    states       = [s.strip() for s in states_raw.split(",") if s.strip()]

    # Bypass for testing
    if JPG_STRIPE_TEST_BYPASS or not JPG_STRIPE_SECRET_KEY:
        payment_id = f"bypass_{secrets.token_hex(8)}"
        _notify_pacta(review_id, amount_cents, payment_id)
        return redirect(
            f"{BASE_URL}/success?review_id={review_id}"
            f"&payment_id={payment_id}"
            f"&profile_id={profile_id}"
            f"&bypass=true"
        )

    state_str = ", ".join(states) if states else "all applicable states"
    desc      = (
        f"Attorney review of Pacta-generated employment handbook "
        f"— {company_name} ({state_str})"
    )

    success_url = (
        f"{BASE_URL}/success"
        f"?review_id={urllib.parse.quote(review_id)}"
        f"&profile_id={urllib.parse.quote(profile_id)}"
        f"&session_id={{CHECKOUT_SESSION_ID}}"
    )
    cancel_url = (
        f"{BASE_URL}/cancel"
        f"?token={urllib.parse.quote(raw_token)}"
    )

    try:
        session_data = {
            "mode":                                                    "payment",
            "customer_email":                                          user_email,
            "success_url":                                             success_url,
            "cancel_url":                                              cancel_url,
            "metadata[review_id]":                                     review_id,
            "metadata[profile_id]":                                    profile_id,
            "metadata[draft_id]":                                      draft_id,
            "metadata[payment_type]":                                  "attorney_review",
            "line_items[0][quantity]":                                 "1",
            "line_items[0][price_data][currency]":                     "usd",
            "line_items[0][price_data][unit_amount]":                  str(amount_cents),
            "line_items[0][price_data][product_data][name]":           "JPG Law — Attorney Review",
            "line_items[0][price_data][product_data][description]":    desc,
        }
        result       = _stripe_request("POST", "/v1/checkout/sessions", session_data)
        checkout_url = result["url"]
        return redirect(checkout_url)
    except Exception as exc:
        return render_template("error.html", message=str(exc)), 500


@app.route("/webhook", methods=["POST"])
def webhook():
    """
    Stripe webhook — checkout.session.completed.
    Verifies signature, records payment, notifies Pacta.
    """
    payload    = request.get_data()
    sig_header = request.headers.get("Stripe-Signature", "")

    if JPG_STRIPE_WEBHOOK_SECRET:
        # Verify Stripe signature
        try:
            parts      = {k: v for part in sig_header.split(",")
                          for k, v in [part.split("=", 1)]}
            timestamp  = parts.get("t", "")
            signatures = [v for k, v in parts.items() if k == "v1"]
            signed_payload = f"{timestamp}.{payload.decode()}"
            expected   = hmac.new(
                JPG_STRIPE_WEBHOOK_SECRET.encode(),
                signed_payload.encode(),
                hashlib.sha256,
            ).hexdigest()
            if not any(hmac.compare_digest(expected, s) for s in signatures):
                abort(400, "Invalid signature")
        except Exception:
            abort(400, "Signature verification failed")

    try:
        event = json.loads(payload)
    except Exception:
        abort(400, "Invalid JSON")

    if event.get("type") == "checkout.session.completed":
        session    = event["data"]["object"]
        meta       = session.get("metadata", {})
        ptype      = meta.get("payment_type", "")

        if ptype == "attorney_review":
            review_id    = meta.get("review_id", "")
            payment_id   = session.get("id", "")
            amount_cents = session.get("amount_total", 0)
            if review_id:
                _notify_pacta(review_id, amount_cents, payment_id)

    return {"ok": True}


@app.route("/success")
def success():
    review_id  = request.args.get("review_id", "")
    profile_id = request.args.get("profile_id", "")
    bypass     = request.args.get("bypass") == "true"
    return render_template(
        "success.html",
        review_id    = review_id,
        profile_id   = profile_id,
        pacta_url    = PACTA_BASE_URL,
        bypass       = bypass,
    )


@app.route("/cancel")
def cancel():
    raw_token = request.args.get("token", "")
    return render_template(
        "cancel.html",
        engage_url = f"{BASE_URL}/engage?token={urllib.parse.quote(raw_token)}",
        pacta_url  = PACTA_BASE_URL,
    )


@app.errorhandler(400)
@app.errorhandler(404)
@app.errorhandler(500)
def error_handler(e):
    code = getattr(e, "code", 500)
    msg  = getattr(e, "description", str(e))
    return render_template("error.html", code=code, message=msg), code


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5100)), debug=False)

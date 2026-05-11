"""
Payment automation for the SAMA AI license server.

This module keeps billing outside the desktop app. LemonSqueezy is the active
public checkout path; Stripe support remains optional for older deployments.
Successful payment webhooks renew users.subscription_expiry and update the
server-side account/payment profile.
"""

from __future__ import annotations

import hashlib
import hmac
import os
from datetime import datetime, timedelta
from typing import Callable, Literal, Optional

try:
    import stripe
except Exception:  # pragma: no cover - optional legacy provider
    stripe = None
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session


APP_NAME = "SAMA AI"
APP_VERSION = "2.0.0"
APP_BUILD_DATE = "May 2026"
APP_WEBSITE_URL = os.getenv("APP_WEBSITE_URL", "https://samaail.netlify.app/")
APP_DOWNLOAD_URL = os.getenv(
    "APP_DOWNLOAD_URL",
    "https://69fc831415505220d12439eb--profound-sfogliatella-81eec2.netlify.app/#download",
)
LEMONSQUEEZY_CHECKOUT_URL = os.getenv(
    "LEMONSQUEEZY_CHECKOUT_URL",
    "https://samaai.lemonsqueezy.com/checkout/buy/4e1e15f2-b41c-4631-8457-af7aadb738d0",
)

PlanName = Literal["day", "week", "month"]

PLAN_DAYS: dict[str, int] = {
    "day": 1,
    "week": 7,
    "month": 30,
}

PLAN_AMOUNTS_USD: dict[str, int] = {
    "day": 2,
    "week": 10,
    "month": 30,
}

AMOUNT_CENTS_TO_DAYS: dict[int, int] = {
    200: 1,
    1000: 7,
    3000: 30,
}

PLAN_PRICE_ENV: dict[str, str] = {
    "day": "STRIPE_DAY_PRICE_ID",
    "week": "STRIPE_WEEK_PRICE_ID",
    "month": "STRIPE_MONTH_PRICE_ID",
}


class CheckoutSessionRequest(BaseModel):
    email: EmailStr
    plan: PlanName
    app_version: Optional[str] = None


class CheckoutSessionResponse(BaseModel):
    checkout_url: str
    session_id: str
    plan: str
    expected_days: int
    provider: str = "lemonsqueezy"


class BillingStatusResponse(BaseModel):
    email: EmailStr
    active: bool
    expiry: Optional[datetime]
    days_left: int
    account_type: str
    payment_status: str
    is_paid: bool
    payment_url: str = LEMONSQUEEZY_CHECKOUT_URL
    app_name: str = APP_NAME
    app_version: str = APP_VERSION
    app_build_date: str = APP_BUILD_DATE


def create_payment_router(User, get_db: Callable[[], Session]) -> APIRouter:
    router = APIRouter(prefix="/billing", tags=["billing"])

    @router.get("/app-info")
    def app_info():
        return {
            "app_name": APP_NAME,
            "app_version": APP_VERSION,
            "app_build_date": APP_BUILD_DATE,
            "latest_version": os.getenv("APP_LATEST_VERSION", APP_VERSION),
            "minimum_supported_version": os.getenv("APP_MIN_SUPPORTED_VERSION", APP_VERSION),
            "update_available": _env_bool("APP_UPDATE_AVAILABLE"),
            "website_url": APP_WEBSITE_URL,
            "download_url": APP_DOWNLOAD_URL,
            "payment_url": LEMONSQUEEZY_CHECKOUT_URL,
            "plans": {
                name: {"amount_usd": PLAN_AMOUNTS_USD[name], "days": PLAN_DAYS[name]}
                for name in PLAN_DAYS
            },
        }

    @router.get("/payment-link")
    def payment_link():
        return {
            "checkout_url": LEMONSQUEEZY_CHECKOUT_URL,
            "provider": "lemonsqueezy",
            "plans": {
                name: {"amount_usd": PLAN_AMOUNTS_USD[name], "days": PLAN_DAYS[name]}
                for name in PLAN_DAYS
            },
        }

    @router.post("/create-checkout-session", response_model=CheckoutSessionResponse)
    def create_checkout_session(
        data: CheckoutSessionRequest,
        db: Session = Depends(get_db),
    ):
        email = _normalize_email(data.email)
        user = _find_user_by_email(User, db, email)

        if not user:
            raise HTTPException(
                status_code=404,
                detail="Please register the email in the app before payment.",
            )

        if stripe is None or not os.getenv("STRIPE_SECRET_KEY"):
            return CheckoutSessionResponse(
                checkout_url=LEMONSQUEEZY_CHECKOUT_URL,
                session_id="lemonsqueezy-static-checkout",
                plan=data.plan,
                expected_days=PLAN_DAYS[data.plan],
                provider="lemonsqueezy",
            )

        _configure_stripe()
        price_id = _price_id_for_plan(data.plan)

        metadata = {
            "email": email,
            "plan": data.plan,
            "days": str(PLAN_DAYS[data.plan]),
            "app_name": APP_NAME,
            "app_version": data.app_version or APP_VERSION,
        }

        try:
            session = stripe.checkout.Session.create(
                mode="payment",
                customer_email=email,
                client_reference_id=email,
                line_items=[{"price": price_id, "quantity": 1}],
                success_url=_success_url(),
                cancel_url=_cancel_url(),
                allow_promotion_codes=True,
                metadata=metadata,
                payment_intent_data={"metadata": metadata},
            )
        except Exception as exc:
            raise HTTPException(
                status_code=502,
                detail=f"Could not create Stripe Checkout session: {exc}",
            ) from exc

        return CheckoutSessionResponse(
            checkout_url=session.url,
            session_id=session.id,
            plan=data.plan,
            expected_days=PLAN_DAYS[data.plan],
            provider="stripe",
        )

    @router.post("/webhook")
    async def stripe_webhook(request: Request, db: Session = Depends(get_db)):
        if stripe is None:
            raise HTTPException(status_code=503, detail="Stripe provider is not enabled.")
        _configure_stripe()
        webhook_secret = _required_env("STRIPE_WEBHOOK_SECRET")
        payload = await request.body()
        signature = request.headers.get("stripe-signature")

        if not signature:
            raise HTTPException(status_code=400, detail="Missing Stripe signature.")

        try:
            event = stripe.Webhook.construct_event(payload, signature, webhook_secret)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid Stripe payload.") from exc
        except stripe.error.SignatureVerificationError as exc:
            raise HTTPException(status_code=400, detail="Invalid Stripe signature.") from exc

        if event["type"] == "checkout.session.completed":
            _apply_checkout_renewal(User, db, event["data"]["object"])

        return {"received": True}

    @router.post("/lemonsqueezy-webhook")
    @router.post("/lemonsqueezy/webhook")
    async def lemonsqueezy_webhook(request: Request, db: Session = Depends(get_db)):
        payload = await request.body()
        _verify_lemonsqueezy_signature(payload, request.headers.get("x-signature"))

        try:
            event = await request.json()
        except Exception as exc:
            raise HTTPException(status_code=400, detail="Invalid LemonSqueezy payload.") from exc

        event_name = ((event.get("meta") or {}).get("event_name") or "").lower()
        if event_name in {"order_created", "subscription_created", "subscription_payment_success"}:
            _apply_lemonsqueezy_renewal(User, db, event)

        return {"received": True}

    @router.get("/payment-status", response_model=BillingStatusResponse)
    def payment_status(email: EmailStr = Query(...), db: Session = Depends(get_db)):
        normalized_email = _normalize_email(email)
        user = _find_user_by_email(User, db, normalized_email)

        if not user:
            raise HTTPException(status_code=404, detail="User not found.")

        now = datetime.utcnow()
        expiry = user.subscription_expiry
        active = bool(expiry and expiry > now)
        days_left = 0

        if active:
            days_left = max(1, (expiry - now).days + 1)

        return BillingStatusResponse(
            email=normalized_email,
            active=active,
            expiry=expiry,
            days_left=days_left,
            account_type=getattr(user, "account_type", None) or ("paid" if getattr(user, "last_payment_amount", None) else "free"),
            payment_status=getattr(user, "payment_status", None) or ("active" if active else "expired"),
            is_paid=bool((getattr(user, "account_type", None) == "paid") and active),
        )

    @router.get("/success", response_class=HTMLResponse)
    def billing_success(session_id: Optional[str] = None):
        session_note = f"<p>Stripe session: {session_id}</p>" if session_id else ""
        return f"""
        <html>
            <head><title>SAMA AI payment successful</title></head>
            <body style="font-family: Arial, sans-serif; margin: 48px;">
                <h1>Payment successful</h1>
                <p>Your SAMA AI license will update automatically.</p>
                <p>Please return to the app and sign in again or check your license.</p>
                {session_note}
            </body>
        </html>
        """

    @router.get("/cancel", response_class=HTMLResponse)
    def billing_cancel():
        return """
        <html>
            <head><title>SAMA AI payment cancelled</title></head>
            <body style="font-family: Arial, sans-serif; margin: 48px;">
                <h1>Payment cancelled</h1>
                <p>No payment was taken. You can return to the app and try again.</p>
            </body>
        </html>
        """

    return router


def _apply_checkout_renewal(User, db: Session, checkout_session) -> None:
    metadata = _stripe_value(checkout_session, "metadata") or {}
    payment_status = _stripe_value(checkout_session, "payment_status")

    if payment_status != "paid":
        return

    email = _normalize_email(
        metadata.get("email")
        or _stripe_value(checkout_session, "customer_email")
        or ((_stripe_value(checkout_session, "customer_details") or {}).get("email"))
    )
    plan = metadata.get("plan")

    if plan not in PLAN_DAYS:
        raise HTTPException(status_code=400, detail="Unknown payment plan.")

    user = _find_user_by_email(User, db, email)

    if not user:
        raise HTTPException(status_code=404, detail="Paid user was not found.")

    now = datetime.utcnow()
    current_expiry = user.subscription_expiry
    renewal_start = current_expiry if current_expiry and current_expiry > now else now

    _renew_user_license(
        user,
        renewal_start,
        PLAN_DAYS[plan],
        provider="stripe",
        payment_id=_stripe_value(checkout_session, "id"),
        amount_cents=None,
        currency=None,
    )

    db.commit()


def _apply_lemonsqueezy_renewal(User, db: Session, event: dict) -> None:
    data = event.get("data") or {}
    attrs = data.get("attributes") or {}
    meta = event.get("meta") or {}
    custom = meta.get("custom_data") or attrs.get("custom_data") or {}

    email = _normalize_email(
        custom.get("email")
        or attrs.get("user_email")
        or attrs.get("customer_email")
        or attrs.get("email")
    )
    if not email:
        raise HTTPException(status_code=400, detail="LemonSqueezy payment did not include an email.")

    amount_cents = _lemonsqueezy_amount_cents(attrs)
    days = _days_for_paid_amount(amount_cents)
    if not days:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported LemonSqueezy payment amount: {amount_cents} cents.",
        )

    user = _find_user_by_email(User, db, email)
    if not user:
        raise HTTPException(status_code=404, detail="Paid user was not found.")

    now = datetime.utcnow()
    current_expiry = user.subscription_expiry
    renewal_start = current_expiry if current_expiry and current_expiry > now else now
    _renew_user_license(
        user,
        renewal_start,
        days,
        provider="lemonsqueezy",
        payment_id=str(data.get("id") or attrs.get("identifier") or attrs.get("order_number") or ""),
        amount_cents=amount_cents,
        currency=attrs.get("currency") or attrs.get("currency_code") or "USD",
    )

    db.commit()


def _renew_user_license(
    user,
    renewal_start: datetime,
    days: int,
    provider: str,
    payment_id: Optional[str],
    amount_cents: Optional[int],
    currency: Optional[str],
) -> None:
    user.subscription_expiry = renewal_start + timedelta(days=days)
    user.email_verified = True
    if hasattr(user, "account_type"):
        user.account_type = "paid"
    if hasattr(user, "payment_status"):
        user.payment_status = "active"
    if hasattr(user, "last_payment_amount") and amount_cents is not None:
        user.last_payment_amount = f"{amount_cents / 100:.2f}"
    if hasattr(user, "last_payment_currency") and currency:
        user.last_payment_currency = str(currency).upper()
    if hasattr(user, "last_payment_provider"):
        user.last_payment_provider = provider
    if hasattr(user, "last_payment_id") and payment_id:
        user.last_payment_id = payment_id
    if hasattr(user, "last_payment_date"):
        user.last_payment_date = datetime.utcnow()


def _configure_stripe() -> None:
    if stripe is None:
        raise HTTPException(status_code=503, detail="Stripe provider is not enabled.")
    stripe.api_key = _required_env("STRIPE_SECRET_KEY")


def _price_id_for_plan(plan: str) -> str:
    if plan not in PLAN_PRICE_ENV:
        raise HTTPException(status_code=400, detail="Unknown payment plan.")
    return _required_env(PLAN_PRICE_ENV[plan])


def _success_url() -> str:
    return os.getenv("STRIPE_SUCCESS_URL") or _public_url(
        "/billing/success?session_id={CHECKOUT_SESSION_ID}"
    )


def _cancel_url() -> str:
    return os.getenv("STRIPE_CANCEL_URL") or _public_url("/billing/cancel")


def _public_url(path: str) -> str:
    base_url = os.getenv("PUBLIC_BASE_URL") or os.getenv("BASE_URL") or "http://localhost:8000"
    return f"{base_url.rstrip('/')}{path}"


def _required_env(name: str) -> str:
    value = os.getenv(name)
    if not value:
        raise HTTPException(
            status_code=500,
            detail=f"Missing server configuration: {name}",
        )
    return value


def _normalize_email(email: object) -> str:
    if not email:
        return ""
    return str(email).strip().lower()


def _find_user_by_email(User, db: Session, email: str):
    return db.query(User).filter(User.email.ilike(email)).first()


def _stripe_value(obj, key: str, default=None):
    if hasattr(obj, "get"):
        return obj.get(key, default)
    return getattr(obj, key, default)


def _env_bool(name: str) -> bool:
    return os.getenv(name, "").strip().lower() in {"1", "true", "yes", "y"}


def _verify_lemonsqueezy_signature(payload: bytes, signature: Optional[str]) -> None:
    secret = os.getenv("LEMONSQUEEZY_WEBHOOK_SECRET")
    if not secret:
        raise HTTPException(
            status_code=500,
            detail="Missing server configuration: LEMONSQUEEZY_WEBHOOK_SECRET",
        )
    if not signature:
        raise HTTPException(status_code=400, detail="Missing LemonSqueezy signature.")
    expected = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, signature):
        raise HTTPException(status_code=400, detail="Invalid LemonSqueezy signature.")


def _lemonsqueezy_amount_cents(attrs: dict) -> int:
    for key in ("total", "subtotal", "total_usd", "subtotal_usd"):
        value = attrs.get(key)
        if value is None:
            continue
        try:
            amount = float(value)
        except (TypeError, ValueError):
            continue
        if amount <= 0:
            continue
        return int(round(amount if amount >= 100 else amount * 100))
    return 0


def _days_for_paid_amount(amount_cents: int) -> int:
    if amount_cents in AMOUNT_CENTS_TO_DAYS:
        return AMOUNT_CENTS_TO_DAYS[amount_cents]
    # Allow a tiny rounding tolerance from payment processors.
    for expected, days in AMOUNT_CENTS_TO_DAYS.items():
        if abs(amount_cents - expected) <= 2:
            return days
    return 0

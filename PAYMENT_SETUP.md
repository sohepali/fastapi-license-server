# SAMA AI Payment Automation Setup

This server now has Stripe Checkout payment automation in `payment_automation.py`.
The desktop app does not need to trust a payment result from the user. Stripe sends
a signed webhook to the server, and the server extends `users.subscription_expiry`.

## What was added

- `POST /billing/create-checkout-session`
  Creates a Stripe Checkout page for `day`, `week`, or `month`.

- `POST /billing/webhook`
  Receives signed Stripe events and renews the existing license expiry.

- `GET /billing/payment-status?email=user@example.com`
  Shows whether the user has an active license and how many days remain.

- `GET /billing/app-info`
  Returns app version `2.0.0`, build date `May 2026`, and optional update info.

## Recommended prices

Configure these as one-time prices in Stripe:

- Day pass: USD 2
- Week pass: USD 5
- Month pass: USD 30

You can change the prices later in Stripe by creating new Price IDs and updating
the environment variables.

## Stripe dashboard steps

1. Create a Stripe account.
2. In Product catalog, create product `SAMA AI`.
3. Add three one-time prices: day, week, and month.
4. Copy the three Price IDs into:
   - `STRIPE_DAY_PRICE_ID`
   - `STRIPE_WEEK_PRICE_ID`
   - `STRIPE_MONTH_PRICE_ID`
5. In Developers -> Webhooks, add endpoint:
   - `https://your-server-url/billing/webhook`
6. Select this event:
   - `checkout.session.completed`
7. Copy the webhook signing secret into:
   - `STRIPE_WEBHOOK_SECRET`

## Server environment variables

Copy values from `.env.payment.example` into your real server environment.
Do not put live Stripe secrets inside the desktop EXE.

Required:

- `STRIPE_SECRET_KEY`
- `STRIPE_WEBHOOK_SECRET`
- `STRIPE_DAY_PRICE_ID`
- `STRIPE_WEEK_PRICE_ID`
- `STRIPE_MONTH_PRICE_ID`
- `PUBLIC_BASE_URL`
- `ADMIN_RENEW_TOKEN`

## Install dependency

Run this in the server folder:

```powershell
pip install -r requirements.txt
```

## Test flow

1. Register and verify an email in the SAMA AI app.
2. Call:

```http
POST /billing/create-checkout-session
Content-Type: application/json

{
  "email": "user@example.com",
  "plan": "day"
}
```

3. Open the returned `checkout_url`.
4. Pay with a Stripe test card in test mode.
5. Confirm the license with:

```http
GET /billing/payment-status?email=user@example.com
```

## Important security note

The existing manual renewal route `POST /renew/{email}` is now protected by
`ADMIN_RENEW_TOKEN`. To use it manually, send this header:

```http
x-admin-token: your_admin_token
```

Keep this token private.

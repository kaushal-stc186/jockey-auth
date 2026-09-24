# Customer authentication

Shopify Customer Accounts does not render a login form, and the storefront does not either. Shopify redirects the browser to this identity provider. This server responds with its own HTML pages for the phone, OTP, and missing profile fields. After the customer is verified, this server redirects the browser back to Shopify with an authorization code, and Shopify opens the customer session.

The login server is `https://jockey-auth.onrender.com`. It runs on Render’s free tier and sleeps when idle. Open [https://jockey-auth.onrender.com/health](https://jockey-auth.onrender.com/health) first and wait until it returns `{"ok":true}` before testing sign-in.

## Test store

- Store: [https://dev-store-2-ciaderoj.myshopify.com](https://dev-store-2-ciaderoj.myshopify.com)
- Customer account: [https://shopify.com/84275495171/account](https://shopify.com/84275495171/account)

## What must be set

### Shopify identity provider

In Shopify admin: **Settings → Customer accounts → Identity provider**.

| Field | Value |
|---|---|
| Provider | Custom or other |
| Well-known URL | `https://jockey-auth.onrender.com/.well-known/openid-configuration` |
| Client ID | Value of `CLIENT_ID` (`jockey-mobile-auth`) |
| Client secret | Value of `CLIENT_SECRET` |
| Additional scopes | `profile phone` |
| Post-sign-out parameter | `post_logout_redirect_uri` |

`openid` and `email` are requested by Shopify already. `profile` is required for first and last name. `phone` is required for the mobile number.

Callback and sign-out URLs shown on that page must be listed in `REDIRECT_URIS` and `POST_LOGOUT_REDIRECT_URIS`. Shopify calls the token endpoint with HTTP Basic auth (`client_secret_basic`).

### Shopify Admin API

A custom app token with `read_customers` and `write_customers`:

| Env var | Use |
|---|---|
| `SHOPIFY_SHOP` | `dev-store-2-ciaderoj.myshopify.com` |
| `SHOPIFY_ADMIN_ACCESS_TOKEN` | Lookup the customer by phone, then write name and email back |

This token is not the identity-provider client id, and it is not the Customer Account API client id. The Customer Account API client id (`SHOPIFY_CUSTOMER_ACCOUNT_CLIENT_ID`) is for the mobile or web app calling Shopify after login. Web and mobile each have their own. Neither is used during this sign-in.

### This server

| Env var | Required for |
|---|---|
| `ISSUER` | Public URL of this server |
| `CLIENT_ID` / `CLIENT_SECRET` | Shopify calling `/token` |
| `REDIRECT_URIS` | Allowing Shopify's login callback |
| `POST_LOGOUT_REDIRECT_URIS` | Allowing Shopify's logout callback |
| `SHOPIFY_SHOP` / `SHOPIFY_ADMIN_ACCESS_TOKEN` | Reading and updating the Shopify customer |
| `STATIC_OTP` | Optional fixed OTP. If empty, a random 4-digit OTP is used |

The login server keeps its own profile per phone number in our database. That record is separate from the Shopify customer. A name or email already in our database is kept. Shopify is used only to fill a field our database does not have yet. On a successful login, the saved profile is written back to the Shopify customer.

## Sign-in flow

1. The customer starts sign-in on the store.
2. Shopify opens `GET /authorize` with `response_type=code`, `client_id`, `redirect_uri`, `scope`, `state`, `nonce`, and PKCE `code_challenge`.
3. The customer enters an Indian mobile number. The country code is fixed as `+91`. The number must match `^[6-9]\d{9}$`. Pasting or autofilling a full number sends the OTP immediately.
4. The server sends a 4-digit OTP. It expires in 5 minutes. More than 5 wrong attempts requires a new OTP.
5. After the OTP matches, the server loads the phone from our database and from Shopify (`customerByIdentifier` by phone).
6. A field already stored for that phone is kept. Shopify fills a field only when this server does not have it yet.
7. The form asks only for what is still missing:
   - First or last name missing: both name fields. A name that is already known can be changed.
   - Both names present, email missing: email only.
   - Email, first name, and last name all present: no form.
8. The server saves that profile, then updates the Shopify customer with `customerUpdate` (`firstName`, `lastName`, `email`). Login still completes if Shopify rejects the update.
9. The server redirects back to Shopify with a one-time `code` and the original `state`.
10. Shopify posts that code to `POST /token` with the client id and secret. The server returns an access token, a refresh token, and an ID token.
11. Shopify opens the customer session. With customer data sync on, it can also copy empty customer fields from the ID token.

Logout is `GET /logout?post_logout_redirect_uri=...`. The redirect must be in `POST_LOGOUT_REDIRECT_URIS`.

## Where the pages come from

No login UI is installed on the Shopify storefront. The store only starts Shopify's customer sign-in. Shopify then sends the browser to this server's `/authorize` URL. Every page the customer fills in is HTML returned by this server:

| Step | This server returns |
|---|---|
| Start | Phone page. Country code is fixed as `+91`. The customer enters the 10-digit number. |
| After a valid number | OTP page for that number. |
| After a valid OTP, if profile fields are missing | Name and/or email page. Which fields appear is decided by the merge rules below. |
| After the profile is complete | No page. HTTP redirect to Shopify's callback with `code` and `state`. |

The storefront is not involved again until Shopify has exchanged that code and the customer is signed in.

## Validation to implement

Run each check in the page and again on the server. The server result is the one that counts.

### Phone

Keep `+91` fixed. Accept only the national number.

Clean the input before checking it:

- Remove every character that is not a digit.
- 12 digits starting with `91` drop the `91`. `919876543210` becomes `9876543210`.
- 11 digits starting with `0` drop the `0`. `09876543210` becomes `9876543210`.
- More than 10 digits keeps the last 10.

Accept the result only when it matches `^[6-9]\d{9}$`. Store it as `+91` plus those 10 digits.

Typing one digit at a time waits for the submit button. A paste or autofill that arrives as a whole valid number submits immediately and requests the OTP.

### OTP

4 digits. A paste or SMS autofill of all 4 digits submits immediately. The code expires after 5 minutes. More than 5 wrong attempts requires a new code. Resend issues a new code for the same number.

### Name and email

Shown only after the OTP, and only for fields the merge still lacks.

- A name may contain letters, spaces, hyphens, and apostrophes.
- If the first name or the last name is missing, show both name fields. Prefill a name that is already known, and let the customer change either field.
- If both names are present and the email is missing, show the email field only.
- Email must match a normal address, such as `name@example.com`. Reject an email already saved for a different phone number.

## Existing customer and merge

After the OTP, the server looks up the phone in two places:

1. Our database, by phone number.
2. The Shopify customer with that phone (`customerByIdentifier`).

Our database wins when both have a value. Shopify is used only to fill a blank.

| Our database | Shopify | What is kept | What the customer sees |
|---|---|---|---|
| First, last, and email | Anything, including blanks | Our values | Nothing. Login continues. |
| Empty | First, last, and email | Shopify's values | Nothing. Login continues. |
| Email only | No names | Our email | Both name fields |
| Both names | No email | Our names | Email only |
| First name only | Last name and email | Our first name, Shopify's last name and email | Both name fields, first name filled in |
| Last name saved earlier | Last name now blank in Shopify | Our last name | Name fields stay hidden if the first name is also known |

Clearing a name on the Shopify customer does not clear it in our database. The next login still uses the saved name and does not ask again.

When login succeeds, that merged profile is saved in our database and written to the Shopify customer (`firstName`, `lastName`, `email`). If no Shopify customer exists yet for that phone, the write is skipped. Shopify still receives the same name, email, and phone in the ID token and can create the customer from that.

## What the ID token contains

| Claim | Source |
|---|---|
| `sub` | Stable id for the phone |
| `email`, `email_verified` | Saved email |
| `phone_number`, `phone_number_verified` | `+91` number |
| `given_name` | First name |
| `family_name` | Last name |
| `name` | First and last name |

`/userinfo` returns the same profile claims. Access tokens expire in 1 hour. Refresh tokens last 30 days.

## Two different client ids

| Credential | Who uses it |
|---|---|
| `CLIENT_ID` / `CLIENT_SECRET` | Shopify, when it talks to this login server |
| Customer Account API client id | The storefront app, when it calls Shopify after the customer is signed in |

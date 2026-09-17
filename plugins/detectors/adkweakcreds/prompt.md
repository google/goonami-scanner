**Goal**

Identify the most optimized way to test the validity of a credential pair
against the given application. You will identify the right requests to send to
perform such an authentication attempt.

**Steps:**

1.  Identify whether the application supports authentication. If the application
    does not support authentication, you can stop and already provide an empty
    answer.

2.  Prepare a list of credential pairs that should be tested against the
    application.

3.  Does the authentication scheme require a CSRF token?

4.  Formalize what is the best request to send for authentication

**Details for steps:**

1.  Support for authentication

You will first determine IF the application supports authentication, as you will
only be able to proceed if that is the case.

Note: This detector strictly tests for **weak passwords and secrets**. The
application supports authentication only if it requires a secret (e.g. a
username/password pair, an explicit password/PIN field, an HTTP
`Authorization` header, an API key, or a secret token).

Passwordless schemes (such as forms that only ask for a username or email
without any password, magic links, SMS/email OTPs, WebAuthn, or third-party
OAuth/SSO redirects) are **OUT OF SCOPE**. If a service only asks for a
username or email and accepts no password, you MUST report
`supports_authentication: false` and set `authentication_details: null`.

To be able to perform this step, you must first use the `httpclient` tool and
query the content of the index `/` page. Its content should give you elements to
identify the login mechanism or form.

If the index `/` page does not immediately reveal a login form, do not conclude
that authentication is unsupported without further exploration:
- **HTML Links, Forms & Scripts**: Inspect `<a href="...">`,
  `<form action="...">`, and `<script src="...">` tags in the HTML. Look for
  login links, auth routers, client-side bundles, or API paths (e.g. `/login`,
  `/admin`, `/signin`, `/auth`, `/api/v1/auth`).
- **Common Authentication Endpoints**: If `/` is a landing page, splash page,
  or generic portal without direct auth links, actively probe common
  authentication paths: `/login`, `/admin`, `/signin`, `/user/login`, `/auth`,
  or `/api/auth/login`.
- **Single Page Applications (SPAs)**: Many modern applications serve a
  minimal HTML shell at `/`. Look for referenced JavaScript files or API
  routes that handle authentication.

When inspecting responses from `httpclient`, pay close attention to both status
codes and response headers:
- **401 Unauthorized / `Www-Authenticate`**: If the server responds with a 401
  status code and the `headers` map includes `Www-Authenticate: Basic ...`, the
  service supports HTTP Basic Authentication (RFC 7617). Keep this in mind as a
  fallback, but continue searching for a dedicated form-based or API-based login
  endpoint (such as `/login`, `/admin`, or `/auth`) before defaulting to Basic
  Authentication. Only use Basic Authentication if no other login endpoint is found.
- **3xx Redirects / `Location`**: The tool automatically follows in-scope
  redirects within the target service. If you receive a 3xx response, it
  indicates that the redirect points to an external host (indicated by the
  `Location` header). If `/` redirects to an external site or third-party identity
  provider (e.g. `accounts.google.com`, `okta.com`, `login.microsoftonline.com`),
  do not immediately give up. Many platforms (such as Jenkins, Grafana, GitLab,
  or appliance consoles) retain local password login endpoints (e.g. `/login`,
  `/admin`, or `/login?local=true`) for break-glass or administrative access.
  Check common local login paths before concluding the service is out of scope.
  Only report `supports_authentication: false` if no local secret-based login
  mechanism can be found.
- **`Content-Type`**: Inspect the `Content-Type` header to determine whether the
  endpoint is an HTML page (`text/html`) or a JSON/REST API (`application/json`).

For this specific task, you will NEVER call the `httpclient` tool more than 15
times. If you did not find a login page after that, you will consider that
probably the application does not have any.

2.  Prepare a list of credentials

You will create a list of 10 entries of username and password pairs. You will
prioritize in order:

-   Default, well-known default credentials;
-   Credentials derived from the context of the application, gathered on the
    different pages;
-   Common username and password combinations.

**Username and Schema Formatting:**
Observe the input requirements of the login form or API endpoint. If the
application enforces specific username format constraints (e.g. requires a
valid email address like `admin@example.com`, minimum length, or specific
character classes), ALL candidate credentials in `credentials_to_test` MUST
strictly satisfy these format requirements. Never provide plain usernames (like
`admin` or `root`) when the service explicitly expects an email address or
formatted identity.

3.  Does the authentication scheme require a CSRF token?

You must determine if there is a unique token that is generated and required
before each authentication attempt. This token is usually (but not always)
present in the login form with the username and password.

You will not assume anything. You will use the result of the `httpclient` tool
against the login page to determine the presence of such token.

IF there is a CSRF token, identify the right request to send to extract that
CSRF token. Extraction should be a one-subgroup regular expression.

4.  The login request

You will identify the best suited request to perform one authentication attempt.

**Authentication Type Priority:**
You must always prefer logins that are not behind HTTP Basic Authentication (e.g. interactive HTML login forms or dedicated JSON/REST login API endpoints). Only use HTTP Basic Authentication if there is no other login found on the service.

For form-based or API-based authentication (PREFERRED):
- You **MUST** use the placeholder `[[password]]` specifically for the
  secret/password parameter (and optionally `[[username]]` for the user
  identifier, e.g. in the body for POST requests
  `username=[[username]]&password=[[password]]`, or in the URL path). If the
  request also submits a user identifier, you MUST use `[[username]]` for the
  username parameter. You MUST NEVER use `[[password]]` as a substitute for a
  username or user identifier.
- If the endpoint accepts JSON (`Content-Type: application/json`), format the
  POST `body` as a JSON string (e.g. `{"username": "[[username]]", "password": "[[password]]"}`)
  and specify `Content-Type: application/json` in `headers` (e.g. `{"name": "Content-Type", "value": "application/json"}`).
- If the request requires a CSRF token, use `[[csrftoken]]`.

For HTTP Basic Authentication (FALLBACK ONLY - use only if no other login found):
- Use only when the service returns `Www-Authenticate: Basic ...` on 401 Unauthorized and no form or dedicated API login endpoint exists.
- Use `GET` or `POST` targeting the protected path.
- In `headers`, add `{"name": "Authorization", "value": "Basic [[basic_auth]]"}`.
  The engine will automatically populate `[[basic_auth]]` with base64-encoded
  `username:password`.
- Set `csrf_request` to `null`.
- Set `extraction_regex` to match the failure message or error banner in the 401 response body (or `^\s*$` if the 401 response body is empty or contains only whitespace).

The request MUST NOT be static; it must actively use at least the `[[password]]`
or `[[basic_auth]]` placeholder to pass the credentials. No other placeholder is
allowed. Use `[[csrftoken]]` if a CSRF token is required.

You **MUST** identify a unique pattern that will provide proof that the
authentication attempt **failed**. This pattern should only be present after
a failed attempt was performed. This is usually an error message indicating to
the user that the credentials were invalid.

**Distinguishing Credential Rejection from Input/Schema Errors:**
The `extraction_regex` MUST match authentication and credential verification
rejections (such as `Invalid credentials`, `Incorrect username or password`,
`Authentication failed`, `User not found`, or `Bad credentials`).
It MUST NEVER match input syntax or schema-level validation errors (such
as `value is not a valid email address`, `invalid email format`,
`field required`, `string too short`, `malformed json`).
Ensure that candidate credentials pass input schema validation so that
requests reach the actual authentication handler, and ensure your regex tests
credential validity rather than input formatting.

If the failure response body is empty or contains only whitespace (common
for APIs and certain HTTP endpoints that return an empty body on invalid
credentials while returning content on success), use `^\s*$` (or `^$`) as the
`extraction_regex` to match the empty failure response.

Note: Your strategy will be immediately verified against invalid credentials
using the candidate username format. The `extraction_regex` MUST successfully
match the response body of this failed attempt, and it MUST NOT match the
response of a successful login.

**Your answer:**

-   `authentication_details`: Required if the application supports
    password/secret authentication. If the application does NOT support
    password/secret authentication (or is passwordless), you MUST omit this
    field or set it to strictly `null`. Do not provide an object with empty
    fields.
-   `login_request`: Information about the request to send to perform exactly
    one authentication attempt. Prefer form-based or dedicated API login
    requests over HTTP Basic Authentication; only use `[[basic_auth]]` if no
    other login mechanism is found. It must contain a regular expression (e.g.,
    `(Invalid username or password)`, or `^\s*$` if authentication failure
    produces an empty or whitespace-only response body) that allows confirming
    that the authentication attempt failed. Ensure it sets a "Content-Type"
    header should the request require it (e.g. for POST requests).
-   `csrf_request`: ONLY ADDED IF a CSRF token is required. The plugin will
    execute this request, extract the token, and automatically maintain the
    session cookies. You MUST then use the `[[csrftoken]]` placeholder in your
    `login_request`. If a CSRF token is not required by the service, you MUST
    omit this field or set the `csrf_request` field to strictly `null`. Do NOT
    provide a `csrf_request` object with empty fields (like `""`). It must
    contain a one-subgroup regular expression
    (e.g., `name="csrf_token" value="([^"]+)"`).
-   `credentials_to_test`: The list of credentials identified in step 2.

**Available tools:**

-   httpclient: Performs an HTTP request against the service. The arguments
    are the method (e.g. `GET`, `POST`), the URI which starts with a `/` and is
    the absolute path to the resource to query, the headers if you need to add
    additional headers and finally the data to add to the body if needed.
    The tool returns `status_code`, high-signal `headers` (`Content-Type`,
    `Location`, `Www-Authenticate`), and response `content`.
    The tool automatically follows redirects within the target service, but
    will NOT follow redirects to external hosts (returning a 3xx response with
    the external `Location` header).
    If you need to test a multi-step flow (like fetching a CSRF token and then
    logging in), set `maintain_session` to `true` on both requests. This ensures
    session cookies are saved and forwarded. You can also set `clear_session`
    to `true` to wipe any existing cookies before making the request.

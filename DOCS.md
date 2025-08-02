# GOTHIC Technical Documentation

## 1. Introduction

GOTHIC is a Go library designed to provide robust session management, CSRF (Cross-Site Request Forgery) protection, and RBAC (Role-Based Access Control) for web applications, particularly those built with frameworks like Gin. It focuses on security, extensibility, and a clear request processing lifecycle.

---

## 2. Core Concepts

GOTHIC is built around several core concepts that work together to secure and manage application routes.

### 2.1. Session Management
Securely manages user sessions using encrypted cookies. It handles session creation, validation, refresh, and provides a mechanism to associate custom data (claims) with a session.

* **Session Cookies**: Encrypted cookies store session data, including a header with metadata (like expiration and refresh times) and a payload with session claims. Session cookies are structured with a version, key ID, and the encrypted, base64-encoded payload.
* **Session Claims**: Arbitrary key-value pairs can be stored within a session, allowing for flexible data association with users. Special claims like `___session_mode`, `___rbac_id`, `___csrf_token_tie`, and `___version` are used internally.
* **Session Lifecycle**: Sessions can expire and have a separate refresh period. GOTHIC can automatically refresh sessions if they are valid but due for a refresh.

### 2.2. CSRF Protection
Implements the synchronized token pattern (or double submit cookie) for CSRF protection.

* **CSRF Tokens**: A CSRF token is generated and stored in a cookie, and also sent in a custom HTTP header (e.g., `X-CSRF-Token`).
* **Token Tying**: For authenticated sessions, CSRF tokens are "tied" to the session via a claim (`___csrf_token_tie`). This ensures that a CSRF token issued to an anonymous session cannot be used with an authenticated session.
* **CSRF Lifecycle**: CSRF tokens also have expiration and refresh times.

### 2.3. RBAC (Role-Based Access Control)
Provides a flexible RBAC system to control access to resources based on user roles and permissions.

* *Permissions**: Defined as an action (e.g., read, create) on a resource (e.g., "article", "user_profile").
* **Roles**: Collections of permissions.
* **Checking Logic**: Access is granted if:
    * The route requires no specific permissions or roles.
    * The subject is a member of any of the roles explicitly required by the API configuration.
    * The subject directly possesses all permissions required by the API configuration.
    * The combined set of permissions (direct and from all assigned roles) satisfies all permissions required by the API configuration.
* **Caching**: RBAC data (subject permissions, subject roles, role permissions) can be cached to improve performance.

### 2.4. Request Lifecycle and Execution
GOTHIC defines a structured way to handle incoming HTTP requests through its `ExecuteRoute` function. This function orchestrates session handling, CSRF validation, RBAC checks, input processing, business logic execution, and response generation.

---

## 3. Key Components

### 3.1. `SessionManager` Interface
This is the central piece for customizing session behavior. Implementations must provide methods for:
* Retrieving cookie and CSRF configurations (`GetCookieData`, `GetCsrfData`).
* Managing session encryption keys (`GetSessionKey`, `GetOldSessionKey`).
* Fetching the user/subject associated with a session (`FetchSubject`).
* Verifying session validity beyond basic decoding (e.g., checking against a session store) (`VerifySession`).
* Storing session information, if necessary (`StoreSession`).
* Verifying session claims against route-specific configurations (`VerifyClaims`).
* Providing an RBAC manager (`GetRbacManager`).
* Getting a unique identifier for a subject from its claims (`GetSubjectIdentifier`).

A `DefaultSessionManager` is provided, which offers a basic implementation for `VerifyClaims` and `GetRbacManager`.

### 3.2. `APIConfiguration` Struct
This struct defines the security and behavior requirements for a specific route:
* `Allow`, `Block`: Lists of allowed or blocked session types (e.g., "default", "admin").
* `Permissions`, `Roles`: RBAC permissions or roles required for the route.
* `SessionRequired`: Boolean indicating if a session is mandatory (defaults to true).
* `ManualResponse`: Boolean indicating if the handler will manually send the HTTP response (defaults to false).
* `FetchSubject`: Boolean indicating if the subject/user associated with the session should be fetched (defaults to false).
* `RequireCsrf`: Boolean indicating if CSRF protection is enforced for this route (defaults to true).

### 3.3. `Handler` Struct
Passed to the business logic function for a route. It encapsulates all relevant request and session context:
* `BaseRoute`: Application-specific base route components (e.g., database connections).
* `Subject`: The fetched user/subject, if `FetchSubject` was true.
* `Context`: The Gin context (`*gin.Context`).
* `SubjectFetched`: Boolean indicating if the subject was successfully fetched.
* `Claims`: The `SessionClaims` for the current session.
* `SessionGroup`: The group/mode of the current session.
* `SessionHeader`: The `SessionHeader` of the current session.
* `CsrfToken`: The `CompleteCsrfToken` for the request.
* `HasSession`: Boolean indicating if a valid session exists.
* `SessionManager`: The active `SessionManager` instance.

### 3.4. `SessionHeader` and `SessionClaims`
* `SessionHeader`: Contains metadata about the session cookie, such as its group, expiration time (`ExpiresAt`), and refresh time (`RefreshAt`). It can be encoded to/decoded from a base64 string.
* `SessionClaims`: A map (`map[string]string`) to store arbitrary data related to the session. It includes a `HasSession` flag that explicitly indicates if the claims represent a valid session. Provides methods to get, set, and check for claims, and to encode/decode the claims payload to/from a base64 string.

### 3.5. `CompleteCsrfToken` and `CsrfHeader`
* `CsrfHeader`: Contains metadata for the CSRF token, specifically its expiration (`ExpiresAt`) and refresh (`RefreshAt`) times.
* `CompleteCsrfToken`: Embeds `CsrfHeader` and adds the actual `Token` string, the `Tie` (linking it to a session), the token `Version`, and a boolean `Tied` indicating if it's tied to an authenticated session.

---

## 4. Workflow: The Request Lifecycle via `ExecuteRoute`

The `ExecuteRoute` function in `core/executor.go` is the heart of GOTHIC's request processing. It follows a multi-stage process:

1.  **Establish Session Context (`_establishSessionContext`)**:
    * **Extract Session**: Attempts to extract session information (header, claims, group) from cookies using `extractSession`.
        * If `SessionRequired` is true and extraction fails, an unauthorized error is returned.
    * **Extract CSRF Token**: Attempts to extract the CSRF token from the header and cookie using `extractCsrf`.
        * If extraction fails, a new anonymous CSRF token might be set. If `RequireCsrf` is true, an unauthorized error is returned.
    * **Validate Session Header**: If a session header exists, it's validated for expiration and integrity. If `SessionRequired` is true and the header is invalid, an unauthorized error occurs. If not required, the session context is cleared.
    * **Refresh Session**: If the session header is valid and needs refreshing, `SetRefreshCookie` is called.
    * **Verify Claims**: The `SessionManager.VerifyClaims` method is called to check if the session's claims are permissible according to `APIConfiguration` (Allow/Block lists).
        * If `SessionRequired` is true and verification fails, an unauthorized error is returned.
        * If `SessionRequired` is false, but an *existing* optional session fails verification, the session context is cleared.
    * **Validate CSRF Token (`validateCsrf`)**:
        * Checks if the CSRF token itself is valid (not expired).
        * If the session is authenticated (`claims != nil && claims.HasSession`), it verifies that the CSRF token is tied (`csrfToken.Tied`) and that its `Tie` value matches the `CsrfTokenTie` claim in the session. An untied CSRF token with an authenticated session is rejected.
        * If the CSRF token needs refreshing, `AutoSetCsrfCookie` is called.
        * If `RequireCsrf` is true and any CSRF validation fails, an unauthorized error is returned.

2.  **Process RBAC (`processRbac`)**:
    * If `APIConfiguration.Roles` or `APIConfiguration.Permissions` are defined and claims exist:
        * Retrieves the RBAC manager from the `SessionManager`. If not available, an internal server error occurs.
        * Retrieves the `RbacCacheIdentifier` from claims. If missing or invalid, an internal server error occurs.
        * Calls `rbac.CheckPermissions` to validate if the subject meets the required roles/permissions.
        * If the check fails, an unauthorized error is returned.

3.  **Prepare Handler Data (`prepareHandlerData`)**:
    * **Input Validation**: Binds and validates request data (headers, query parameters, JSON body) into a user-defined input struct using `validation.InputData`. If validation fails, a validation error is returned.
    * **Fetch Subject**: If `APIConfiguration.FetchSubject` is true and a valid session with claims exists, `SessionManager.FetchSubject` is called to retrieve the user/subject data. If fetching fails, an internal server error is returned.

4.  **Execute Business Logic Handler**:
    * The application-specific handler function is called with the validated input and the `Handler` struct, which contains all context (session, CSRF, subject, etc.).
    * The handler returns an output struct and an optional `*errors.AppError`. If an error is returned, it's sent to the client via `helpers.ErrorResponse`.

5.  **Process Handler Output and Send Response (`processAndSendHandlerOutput`)**:
    * If `APIConfiguration.ManualResponse` is true, GOTHIC does nothing further with the response.
    * Otherwise, the output from the handler is validated using `validation.OutputData`. This also extracts any response headers defined via struct tags in the output struct. If validation fails, a validation error is returned.
    * If successful, `helpers.SuccessResponse` sends a JSON response to the client.

---

## 5. Security Mechanisms

### 5.1. Cookie Encryption and Structure

* **Session Cookies**:
    * **Structure**: `Version Delimiter KeyID Delimiter Base64(AES-GCM(Header Delimiter Payload))`.
        * `Version`: Version of the session cookie format (e.g., "SG1").
        * `KeyID`: Identifier for the encryption key used.
        * `Header`: JSON marshaled `SessionHeader` (group, expiresAt, refreshAt), then base64 encoded.
        * `Payload`: JSON marshaled `SessionClaims`, then base64 encoded.
    * **Encryption**: The combined `Header Delimiter Payload` string is encrypted using AES-GCM. The `KeyID` and `Version` are used as associated data (AD) for the encryption, ensuring that the cookie cannot be decrypted with a different key ID or interpreted under a different version even if the raw ciphertext is the same. The encryption key is retrieved via `SessionManager.GetSessionKey()` or `GetOldSessionKey(keyId)`.

* **CSRF Cookies**:
    * **Structure**: `Version Delimiter KeyID Delimiter Base64(AES-GCM(CompleteCsrfToken))`.
        * `Version`: Version of the CSRF cookie format (e.g., "CG1").
        * `KeyID`: Identifier for the encryption key used.
        * `CompleteCsrfToken`: JSON marshaled `CompleteCsrfToken` struct (includes `CsrfHeader`, `Token`, `Tie`, `Version`, `Tied`).
    * **Encryption**: The JSON marshaled `CompleteCsrfToken` is encrypted using AES-GCM. The `KeyID` and `Version` are used as associated data.

### 5.2. CSRF Token Generation and Validation Flow

1.  **Generation (`CreateCsrfToken`, `AutoSetCsrfCookie`)**:
    * A random token string is generated.
    * A `CompleteCsrfToken` struct is populated with the token, version, tied status (based on whether `csrfTie` is provided), and a new `CsrfHeader` (with expiration/refresh times).
    * This struct is JSON marshaled and then encrypted using AES-GCM with a key from `SessionManager.GetSessionKey()`. The key ID and token version are used as associated data.
    * The final string (version, key ID, encrypted token) is set as a cookie.
    * `AutoSetCsrfCookie` handles whether to generate a tied token (if claims are provided) or an anonymous one (if claims are nil).

2.  **Extraction (`extractCsrfParts`, `extractCsrf`)**:
    * The CSRF token value is read from the `X-CSRF-Token` header (or configured name) and the corresponding cookie. They must match.
    * The cookie string is parsed to get the version, key ID, and encrypted payload.
    * The appropriate decryption key is fetched using `SessionManager.GetOldSessionKey(keyId)`.
    * The payload is decrypted using AES-GCM (with key ID and version as associated data) and then JSON unmarshaled into a `CompleteCsrfToken` struct.

3.  **Validation (`validateCsrf` in `executor.go`)**:
    * The extracted `CompleteCsrfToken` must be present and valid (e.g., not expired).
    * **Tying Check**:
        * If the user has an authenticated session (`claims != nil && claims.HasSession`):
            * The CSRF token *must* be tied (`csrfToken.Tied == true`).
            * The `csrfToken.Tie` value *must* match the `CsrfTokenTie` claim stored in the session claims.
        * If these conditions are not met, it's considered a CSRF mismatch, and the request is rejected (if `RequireCsrf` is true).
    * **Refresh**: If the token `NeedsRefresh()`, `AutoSetCsrfCookie` is called to issue a new one.

---

## 6. Extensibility

### 6.1. Implementing Custom `SessionManager`
Developers can provide their own implementation of the `core.SessionManager` interface to integrate GOTHIC with different data stores, key management systems, or custom session validation logic. This involves defining how:
* Session keys are fetched and rotated.
* Subjects (users) are loaded based on session claims.
* Session state is verified (e.g., against a server-side blacklist).
* Custom claim verification logic is applied.

The `examples/bare_bones/session.go` and `examples/rbac/session.go` files show mock implementations.

### 6.2. Implementing Custom RBAC `Manager`
The `rbac.Manager` interface can be implemented to define how roles and permissions are sourced (e.g., from a database, configuration file, or external service). This includes:
* `GetSubjectRolesAndPermissions`: How to get direct permissions and roles for a user.
* `GetRolePermissions`: How to get permissions associated with a specific role.
* `GetCache`, `GetSubjectPermissionsCacheTtl`, `GetRolePermissionsCacheTtl`: Configuration for caching RBAC data.

The `examples/rbac/rbac.go` file provides a sample `MyRbacManager`. `rbac.DefaultRBACManager` offers a base with Ristretto caching.

---

## 7. Error Handling

### 7.1. `AppError` Structure
GOTHIC uses a custom `AppError` struct for standardized error handling:
* `Code`: HTTP status code for the response.
* `Message`: User-friendly error message for the client.
* `Err`: The underlying original error (for logging, not typically sent to client in production).
* `Details`: Optional structured data about the error for the client.

It implements the standard `error` interface and provides a `ToJSONResponse(production bool)` method to format the error for client consumption, conditionally including the underlying error details if not in production mode.

### 7.2. Common Error Types
The `errors` package defines helper functions to create common `AppError` types:
* `NewBadRequest` (400)
* `NewUnauthorized` (401)
* `NewForbidden` (403)
* `NewNotFound` (404)
* `NewConflict` (409)
* `NewInternalServerError` (500)
* `NewValidationFailed` (422) - Often wraps `validator.ValidationErrors`.

---

## 8. Helper Utilities (`helpers` package)

The `helpers` package provides various utility functions:

* **Symmetric Encryption (`symetric_encryption.go`)**:
    * `GenerateSymmetricKey`: Generates AES keys (16, 24, or 32 bytes).
    * `SymmetricEncrypt`, `SymmetricDecrypt`: AES-GCM encryption/decryption, allowing for associated data.
* **Response Formatting (`response.go`)**:
    * `ErrorResponse`: Sends a JSON error response using `AppError`.
    * `SuccessResponse`: Sends a JSON success response, optionally setting headers.
* **ID Generation (`id.go`)**:
    * `GenerateID`: Creates a random string of a given length using a charset.
* **HMAC (`hmac.go`)**:
    * `GenerateHMACSignature`, `VerifyHMACSignature`: For HMAC-SHA256 operations.
* **Default Values (`default.go`)**:
    * Functions like `DefaultString`, `DefaultBool`, `DefaultInt`, `DefaultTimeDuration` provide a default value if the input is its zero value.
* **Interfaces (`interfaces.go`)**: Defines generic `SubjectLike` and `BaseRouteComponents` interfaces for type hinting.

---

## 9. Validation (`validation` package)

GOTHIC uses a validation system for request inputs and handler outputs.

### 9.1. Input Validation (`input.go`)
* `InputData[T any](ctx *gin.Context)`:
    * Binds request data (headers via `ShouldBindHeader`, query parameters via `ShouldBindQuery`, and JSON body via `ShouldBindJSON` for relevant methods) into a struct of type `T`.
    * Validates the populated struct using a `validator.Validate` instance (a default one is created if `CustomValidator` is not initialized via `InitValidator`).
    * Returns the validated struct or an `AppError` (typically `NewValidationFailed`).

### 9.2. Output Validation (`output.go`)
* `OutputData[Output any](output *Output)`:
    * Validates the handler's output struct using `CustomValidator`.
    * Extracts response headers from fields tagged with `header:"Header-Name"` in the output struct.
    * Returns a map of headers, the validated output, and an `AppError` if validation fails.

The validator instance can be customized application-wide by calling `validation.InitValidator(v *validator.Validate)`.
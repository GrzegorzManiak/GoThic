# GoThic Technical Documentation

This document provides a concise overview of GoThic's modules and their responsibilities. For installation and a minimal quick start, see GETTING_STARTED.md. For implementation details and design rationale refer to DOCS.md (this file) and the code comments. For testing guidance see TESTING.md.

---

## Project overview

GoThic is a low-level Go toolkit that offers primitives for secure session management, CSRF protection, and role-based access control (RBAC). It is intended as a foundation that apps can integrate and extend rather than a turnkey framework.

---

## Module: core

Purpose: Orchestrates request handling, session lifecycle, CSRF interactions and ties together session managers, route configuration and handler execution.

Key concepts and types:
- SessionHeader: Encodes session metadata (issued at, lifetime, refresh period) and provides Encode/Decode, IsExpired, NeedsRefresh, IsValid helpers.
- SessionClaims: Map-based claims storage with helpers for Get/Set/SetIfNotSet, EncodePayload/DecodePayload.
- SessionManager interface: Pluggable contract for session key management, verification, storage, subject fetching and RBAC integration. DefaultSessionManager provides a minimal VerifyClaims implementation.
- APIConfiguration & Handler: Route-level configuration (Allow/Block, Permissions, Roles, SessionRequired, RequireCsrf, etc.) and the context passed to handlers.
- RouteConstructor: Shorthand to register routes without repeating BaseRoute, SessionManager, and ValidationEngine for every verb.

Where to look: core/*.go (handler.go, session_header.go, session_claims.go, session_manager.go, executor and authorization helpers)

Code example (SessionHeader / SessionClaims):

```go
// Create a header and encode it to a base64 string
hdr := core.NewSessionHeader(false, 30*time.Minute, 10*time.Minute)
encoded, err := hdr.Encode()
if err != nil {
    // handle error
}

// Decode back from string
decoded, err := core.Decode(encoded)
if err != nil {
    // handle error
}

// Work with claims
claims := &core.SessionClaims{}
claims.SetClaim("user_id", "123")
if v, ok := claims.GetClaim("user_id"); ok {
    _ = v // use user id
}

// VerifyClaims using DefaultSessionManager
mgr := &core.DefaultSessionManager{}
ok, err := mgr.VerifyClaims(context.Background(), claims, &core.APIConfiguration{Allow: []string{"default"}})
_ = ok; _ = err
```

Shorthand registration with RouteConstructor:

```go
validationEngine := validation.NewEngine(nil)
routeCtor := core.NewRouteConstructor(router, baseRoute, sessionManager, validationEngine)

routeCtor.GET("/health", publicConfig, HealthHandler)
routeCtor.POST("/profile", authConfig, UpdateProfileHandler)
```

---

## Module: cache

Purpose: Lightweight cache wrappers used by RBAC and optional session caching. Provides basic get/set/ttl semantics used by other modules for performance.

Where to look: cache/cache.go

Code example (basic cache usage):

```go
// Obtain a cache instance from a SessionManager or rbac.Manager implementation
c, _ := mySessionManager.GetCache()
_ = c.Set(context.Background(), "key", []byte("value"), 5*time.Minute)
val, err := c.Get(context.Background(), "key")
_ = val; _ = err
```

---

## Module: errors

Purpose: Standardized application error representation and helpers to construct common HTTP error responses.

Key concepts:
- AppError: Structured error with Code, Message, Err (underlying error) and Details. Methods: Error(), Unwrap(), ToJSONResponse(production bool).
- Convenience constructors: NewBadRequest, NewUnauthorized, NewForbidden, NewNotFound, NewConflict, NewInternalServerError, NewValidationFailed.

Where to look: errors/*.go

Code example (constructing and formatting errors):

```go
// In handlers you typically return an *errors.AppError to the framework
// (see examples/bare_bones/routes.go for complete handler examples):
return nil, errors.NewInternalServerError("Failed to issue session cookie", err)

// Or, when handling a Gin context directly, use helpers.ErrorResponse to write
// the HTTP response immediately:
helpers.ErrorResponse(ctx, errors.NewBadRequest("invalid input", fmt.Errorf("field x missing")))
```

---

## Module: helpers

Purpose: Utility functions used across packages.

Key features:
- Symmetric encryption helpers (AES-GCM) for cookie payloads and CSRF tokens.
- Response helpers to send JSON success and error responses with optional headers.
- ID generation utilities and HMAC helpers used for signing or tying tokens.
- Default value helpers for common zero-value fallbacks.

Where to look: helpers/*.go

Code example (symmetric encryption and response helpers):

```go
// Generate a 32-byte AES key
key, _ := helpers.GenerateSymmetricKey(helpers.AESKeySize32)

// Encrypt / Decrypt with associated data
ciphertext, _ := helpers.SymmetricEncrypt(key, []byte("payload"), []byte("ad"))
plaintext, _ := helpers.SymmetricDecrypt(key, ciphertext, []byte("ad"))
_ = plaintext

// Using response helpers in a Gin handler
helpers.SuccessResponse(ctx, http.StatusOK, map[string]string{"message": "ok"}, map[string]string{"X-Trace": "abc"})
```

---

## Module: rbac

Purpose: Role-based access control primitives and enforcement flow.

Key concepts:
- Permission type and operations (Set, Unset, Has, And, Or, Marshal/Unmarshal, Serialize/Deserialize).
- Manager interface: Pluggable provider for subject roles/permissions and role permissions with caching support.
- Enforcement: Utilities that combine subject permissions and roles to check whether a route's APIConfiguration is satisfied.

Where to look: rbac/*.go

Code example (permissions and enforcement):

```go
// Create permissions and combine them
p := rbac.NewPermission(0)
p.Set(1) // set permission bit 1
p.Set(2) // set permission bit 2

// Check membership
check := rbac.NewPermission(1)
check.Set(2)
if p.Has(check) {
    // allowed
}

// Use rbac.CheckPermissions (example signature)
// allowed, err := rbac.CheckPermissions(ctx, manager, subjectID, config.GetFlatPermissions())
```

+ Additional example: named permission vars and role mappings

```go
import "github.com/grzegorzmaniak/gothic/rbac"

// Define named permission bits (bit indexes are arbitrary but consistent)
var (
    ReadPerm  = rbac.NewPermission(0) // read = bit 0 - 0001
    WritePerm = rbac.NewPermission(1) // write = bit 1 - 0010
    DeletePerm = rbac.NewPermission(2) // delete = bit 2 - 0100
)

// Define role -> permissions mapping using Permissions.Flatten()
var RolePermissions = map[string]rbac.Permission{
    "user":  rbac.Permissions{ReadPerm}.Flatten(), // - 0001
	// Permissions is a slice of Permission with built in methods to
	// combine them into a singular Permission bitset
    "admin": rbac.Permissions{ReadPerm, WritePerm, DeletePerm}.Flatten(), // - 0111
}

// Example check: ensure a role includes the required permission
required := WritePerm // action we want to check
if RolePermissions["admin"].Has(required) {
    // admin has write permission
}
if !RolePermissions["user"].Has(required) {
    // user does not have write
}
```

---

## Module: validation

> Validation is performed automatically by the framework when handlers return data; you don't need to call these helpers explicitly.

Purpose: Input and output validation utilities built on go-playground/validator.

Key features:
- Engine: Holds the validator instance and dynamic struct cache.
- InputData and BindInput: Bind request headers, query params and JSON body, then validate using an Engine.
- OutputData: Validate handler outputs and extract response headers specified via struct tags.
- NewEngine: Create a validation Engine (default validator when nil).

Where to look: validation/*.go

Code example (binding and validating input/output):

```go
// Build an Engine once (app setup) and reuse it.
engine := validation.NewEngine(nil)

// Input binding inside a handler
input, err := validation.InputData[MyInput](ctx, engine)
if err != nil {
    helpers.ErrorResponse(ctx, err)
    return
}

// Output validation before sending
headers, out, err := validation.OutputData(engine, &MyOutput{Message: "ok"})
if err != nil {
    helpers.ErrorResponse(ctx, err)
    return
}
helpers.SuccessResponse(ctx, http.StatusOK, out, headers)
```

+ Additional example: Custom validator and validation tags

```go
import (
	"log"
	"strings"

	"github.com/go-playground/validator/v10"
	"github.com/grzegorzmaniak/gothic/validation"
)

// 1. Define your custom validation function.
// This example checks if a string contains the word "gothic".
func isGothic(fl validator.FieldLevel) bool {
	return strings.Contains(fl.Field().String(), "gothic")
}

// 2. In your application's setup, before defining routes,
// create and configure the validator.
func setupValidator() {
	// Create a new validator instance
	v := validator.New()

	// Register your custom validation
	err := v.RegisterValidation("is-gothic", isGothic)
	if err != nil {
		log.Fatalf("failed to register custom validation: %v", err)
	}

	// Build a validation engine with your custom validator.
	validationEngine := validation.NewEngine(v)
	_ = validationEngine
}

// 3. Use the custom tag in your structs.
type MyInput struct {
	Name string `json:"name" validate:"required,is-gothic"`
}

// The framework will now use your custom validator.
// An input like {"name": "this is gothic"} will pass,
// but {"name": "this is not"} will fail validation.
```

---

## Module: examples

Purpose: Minimal example apps that show how to implement a SessionManager and RBAC manager and wire GoThic into an HTTP framework.

Notes: Examples are not part of the core library and are provided for illustration only. See examples/bare_bones and examples/rbac.

Code example (run an example):

```bash
# from repository root
go run ./examples/bare_bones
# or run the rbac example
go run ./examples/rbac
```

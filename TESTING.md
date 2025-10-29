
## Package: validation

| Test file | Description |
|---|---|
| validation/input_test.go | Tests input binding from JSON, headers and query params and validation behavior for various HTTP methods and edge cases. |
| validation/output_test.go | Tests output validation and header extraction for response structs, including edge cases and nested structs. |
| validation/validator_test.go | Tests initialization and defaulting behavior of the package-level validator instance. |

## Package: helpers

| Test file | Description |
|---|---|
| helpers/default_test.go | Tests helper functions that return default values for strings, bools, ints, int64 and durations. |
| helpers/id_test.go | Tests ID generation and parsing helpers (unique ID behavior). |
| helpers/response_test.go | Tests HTTP success and error response helpers including headers, status codes, and production vs development behavior. |
| helpers/symetric_encryption_test.go | Tests symmetric encryption helpers for correct encryption/decryption behavior. |

## Package: cache

| Test file | Description |
|---|---|
| cache/cache_test.go | Tests cache wrapper behavior (basic interactions and simple expectations). |

## Package: core

| Test file | Description |
|---|---|
| core/session_claims_test.go | Tests SessionClaims methods: get/set, existence checks and payload encode/decode and error cases. |
| core/session_header_test.go | Tests session header parsing/serialization and validation logic. |

## Package: errors

| Test file | Description |
|---|---|
| errors/common_errors_test.go | Tests convenience functions for constructing common AppError types (BadRequest, Unauthorized, etc.). |
| errors/app_error_test.go | Tests AppError methods: Error(), Unwrap(), formatting validation errors and JSON response behavior. |

## Package: rbac

| Test file | Description |
|---|---|
| rbac/permissions_test.go | Tests Permission creation, bit operations (set/unset/has/and/or), (de)serialization and edge cases. |
| rbac/cache_test.go | Tests RBAC cache wrapper behavior and simple caching semantics. |
| rbac/enforcer_test.go | Tests RBAC enforcement logic, ensuring decisions and rule application behave as expected. |
| rbac/fetch_role_test.go | Tests fetching roles logic and parsing of role-related data. |
| rbac/fetch_subject_test.go | Tests fetching subjects for RBAC decisions (subject lookup/parsing). |
| rbac/rbac_test.go | Higher-level RBAC tests that exercise manager orchestration and integration points. |
[![Go Report Card](https://goreportcard.com/badge/github.com/grzegorzmaniak/gothic)](https://goreportcard.com/report/github.com/grzegorzmaniak/gothic)


# GoThic - Go Token Handler for Identity and Control

GoThic is a Go library designed to provide robust session management, CSRF (Cross-Site Request Forgery) protection, and RBAC (Role-Based Access Control) for web applications, particularly those built with frameworks like Gin. It focuses on security, extensibility, and a clear request processing lifecycle.

## Wait!

No, this dose doesn't intend to be an easy-to-use library. It is a low-level library that provides a lot of flexibility and extensibility. It is not a plug-and-play solution, but rather a toolkit for building your own session management and security features.

## Core Features

* **Secure Session Management**: Manages user sessions using encrypted cookies, handling creation, validation, refresh, and association of custom data (claims) with a session.
* **CSRF Protection**: Implements the synchronized token pattern (double submit cookie). CSRF tokens can be tied to authenticated sessions.
* **Role-Based Access Control (RBAC)**: Provides a flexible system to control access to resources based on user roles and permissions, with caching capabilities.
* **Structured Request Lifecycle**: Defines a clear process for handling HTTP requests via its `ExecuteRoute` function, encompassing session handling, CSRF validation, RBAC checks, input processing, business logic execution, and response generation.

## Simple Setup Guide

This guide provides a basic setup using the Gin framework.

### Prerequisites

* Go (latest version recommended)
* Gin Web Framework (`github.com/gin-gonic/gin`)

### Installation

```bash
go get github.com/grzegorzmaniak/gothic
```

### Basic Usage

Here's a simplified example to illustrate how to integrate GOTH into a Gin application. This is based on the "bare\_bones" example provided with the library.

**1. Define Your Application-Specific Structs**

You'll typically define structs for your application's base route components and user model.

```go
package main

// AppSpecificBaseRoute might contain database connections, loggers, etc.
type AppSpecificBaseRoute struct {
    AppName string
}

// AppSpecificUser represents your user model.
type AppSpecificUser struct {
    ID       string
    Username string
    Email    string
    IsActive bool
}
```

**2. Implement a Session Manager**

You need to implement the `core.SessionManager` interface. For a simple start, you can embed `core.DefaultSessionManager` and provide the necessary methods.

```go
package main

import (
	"context"
	"github.com/grzegorzmaniak/gothic/core"
	// "github.com/grzegorzmaniak/goth/rbac" // Include if using RBAC
)

type AppSessionManager struct {
	core.DefaultSessionManager[*AppSpecificUser] // Embed default manager for your user type
	CookieDataConfig *core.SessionCookieData
	CsrfDataConfig   *core.CsrfCookieData
	SessionKeyValue  *[]byte
	// RbacManager      rbac.Manager // Uncomment and implement if using RBAC
}

// GetCookieData returns cookie configuration.
func (m *AppSessionManager) GetCookieData() *core.SessionCookieData {
	return m.CookieDataConfig
}

// GetCsrfData returns CSRF configuration.
func (m *AppSessionManager) GetCsrfData() *core.CsrfCookieData {
	return m.CsrfDataConfig
}

// GetSessionKey returns the current encryption key for sessions.
func (m *AppSessionManager) GetSessionKey() (*[]byte, string, error) {
	return m.SessionKeyValue, "your-key-id-1", nil // Provide a key ID
}

// GetOldSessionKey returns an old encryption key (for key rotation).
func (m *AppSessionManager) GetOldSessionKey(keyID string) (*[]byte, error) {
	// For simplicity, returning the same key. Implement proper key rotation in production.
	if keyID == "your-key-id-1" {
		return m.SessionKeyValue, nil
	}
	return nil, fmt.Errorf("unknown key ID: %s", keyID)
}

// FetchSubject retrieves a user based on session claims.
func (m *AppSessionManager) FetchSubject(ctx context.Context, claims *core.SessionClaims) (*AppSpecificUser, error) {
	// Implement logic to fetch your user, e.g., from a database
	// For this example, returning a mock user.
	userID, ok := claims.GetClaim("user_id")
	if !ok {
		return nil, fmt.Errorf("user_id claim not found")
	}
	return &AppSpecificUser{ID: userID, Username: "TestUser"}, nil
}

// VerifySession can add custom session validation logic (e.g., check against a session store).
func (m *AppSessionManager) VerifySession(ctx context.Context, claims *core.SessionClaims, header *core.SessionHeader) (bool, error) {
	return true, nil // Basic implementation
}

// StoreSession can store session information if needed.
func (m *AppSessionManager) StoreSession(ctx context.Context, claims *core.SessionClaims, header *core.SessionHeader) error {
	return nil // Basic implementation
}

// GetSubjectIdentifier returns a unique identifier from claims for RBAC.
func (m *AppSessionManager) GetSubjectIdentifier(claims *core.SessionClaims) (string, error) {
    // Example: Get user ID from claims
    userID, ok := claims.GetClaim("user_id_for_rbac")
    if !ok {
        return "", fmt.Errorf("RBAC identifier claim not found")
    }
    return userID, nil
}

// GetRbacManager returns your RBAC manager if you're using RBAC.
// func (m *AppSessionManager) GetRbacManager() rbac.Manager {
// 	 return m.RbacManager // Return your rbac.Manager implementation
// }
```

**3. Define Input and Output Structs for Your Handler**

```go
package main

// ExampleInput for request data binding and validation.
type ExampleInput struct {
	QueryParam string `form:"queryParam" validate:"required,alphanum,min=3,max=50"`
}

// ExampleOutput for structuring your handler's response.
type ExampleOutput struct {
	ResultMessage string `json:"result_message"`
	CustomHeader  string `header:"X-Example-Output" json:"-" validate:"required"`
}
```

**4. Define Your Route Handler Function**

```go
package main

import (
	"fmt"
	"github.com/grzegorzmaniak/gothic/core"  // GOTH's core package
	"github.com/grzegorzmaniak/gothic/errors" // GOTH's errors package
)

// AppHandlerContext is an alias for core.Handler with your specific types.
type AppHandlerContext = core.Handler[*AppSpecificBaseRoute, AppSpecificUser]

// BasicActionHandler is an example endpoint handler.
func BasicActionHandler(input *ExampleInput, data *AppHandlerContext) (*ExampleOutput, *errors.AppError) {
	// Example: Issue a new session
	newSessionClaims := &core.SessionClaims{}
	newSessionClaims.SetClaim("user_id", "123")
	newSessionClaims.SetClaim("role", "user")

	err := core.SetSessionCookie(
		data.Context,
		data.SessionManager,
		"guest_session", // Session group/mode
		newSessionClaims,
	)
	if err != nil {
		return nil, errors.NewInternalServerError("Failed to issue session cookie", err)
	}

	resultMsg := fmt.Sprintf("Processed queryParam: '%s'. A new session cookie has been issued.", input.QueryParam)
	return &ExampleOutput{
		ResultMessage: resultMsg,
		CustomHeader:  "ActionProcessed-" + input.QueryParam,
	}, nil
}
```

**5. Initialize GOTH and Gin, and Define Routes**

```go
package main

import (
	"fmt"
	"log"
	"github.com/gin-gonic/gin"
	"github.com/grzegorzmaniak/gothic/core"    // GOTH's core package
	"github.com/grzegorzmaniak/gothic/helpers" // GOTH's helpers package
	// "github.com/grzegorzmaniak/gothic/validation" // If using GOTH's validator
	// validator "github.com/go-playground/validator/v10" // If providing custom validator
)

func main() {
	// Generate a session encryption key (store this securely in production!)
	sessionKey, err := helpers.GenerateSymmetricKey(helpers.AESKeySize32) //
	if err != nil {
		log.Fatalf("Failed to generate session key: %v", err)
	}

	// Initialize your application's base route components.
	baseRoute := &AppSpecificBaseRoute{
		AppName: "MyGothApp",
	}

	// Create an instance of your session manager.
	mySessionManager := &AppSessionManager{
		SessionKeyValue: &sessionKey,
		CookieDataConfig: &core.SessionCookieData{ // Sensible defaults
			Secure:   true, // false for localhost development if not using HTTPS
			HttpOnly: true,
			SameSite: "Strict",
			Path:     "/",
		},
		CsrfDataConfig: &core.CsrfCookieData{ // Sensible defaults
			Secure:   true, // false for localhost development
			HttpOnly: false, // CSRF cookie needs to be readable by JS if sending via header
			SameSite: "Strict",
			Path:     "/",
		},
		// RbacManager: &MyRbacManager{}, // Initialize if using RBAC
	}

	// Optional: Initialize GOTH's validator or provide your own.
	// validation.InitValidator(validator.New()) //

	// Setup Gin router.
	router := gin.Default()

	// Define an API configuration for your route.
	basicActionConfig := &core.APIConfiguration{
		SessionRequired: false,          // Does this route require a session?
		Allow:           []string{"guest_session"}, // Allowed session groups/modes
		RequireCsrf:     true,           // Enforce CSRF protection? Default true.
		// FetchSubject:    true,        // Should GOTH fetch the user object?
	}

	// Define a route.
	router.GET("/myaction", func(ctx *gin.Context) {
		core.ExecuteRoute(ctx, baseRoute, basicActionConfig, mySessionManager, BasicActionHandler)
	})

	// Start the server.
	httpAddr := fmt.Sprintf("localhost:%s", "8080")
	fmt.Printf("Starting server on %s\n", httpAddr)
	if err := router.Run(httpAddr); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
}
```

This setup provides a basic framework. You'll need to:

* Implement the `SessionManager` methods fully (e.g., `WorkspaceSubject` to load users from your database).
* If using RBAC, implement `rbac.Manager` and configure it in your `SessionManager`.
* Securely manage your session encryption keys.
* Customize `APIConfiguration` for each route according to its security requirements.

## Further Information

For more detailed information on GOTH's components, workflow, and advanced configurations (like RBAC and custom session stores), please refer to the technical documentation (`DOCS.md`).
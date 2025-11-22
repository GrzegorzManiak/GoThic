package main

import (
	"fmt"
	"time"

	"github.com/grzegorzmaniak/gothic/core"
	"github.com/grzegorzmaniak/gothic/errors"
	"github.com/grzegorzmaniak/gothic/rbac"
	"github.com/grzegorzmaniak/gothic/validation"
)

// AppHandlerContext is a type alias for the specific instantiation of core.Handler
type AppHandlerContext = core.Handler[*AppSpecificBaseRoute]

// BasicActionHandlerConfig defines the API access configuration for the BasicActionHandler.
var BasicActionHandlerConfig = &core.APIConfiguration{
	SessionRequired: false,
	Allow:           []string{"guest_session"},
	RequireCsrf:     false,
}

// ExampleInput defines a sample input structure for handlers.
type ExampleInput struct {
	// `form` tag for binding query parameters.
	// `json` tag for binding JSON body.
	// `validate` tags for field validation (using your chosen validator library).
	QueryParam string `form:"queryParam" validate:"required,alphanum,min=3,max=50"`
	// Message    string `json:"message" validate:"omitempty,max=200"` // Example if expecting JSON
}

// ExampleOutput defines a sample output structure for handlers.
type ExampleOutput struct {
	// `json` tag for JSON response body.
	// `header` tag for setting response headers. `json:"-"` excludes it from the JSON body.
	ResultMessage string   `json:"result_message"`
	CustomHeader  string   `header:"X-Example-Output" json:"-" validate:"required"`
	Claims        []string `json:"claims,omitempty"`         // Example of including claims in the output
	CsrfToken     string   `json:"csrf_token,omitempty"`     // Example of including CSRF token in the output
	CsrfTokenTie  string   `json:"csrf_token_tie,omitempty"` // Example of including CSRF token tie in the output
	CsrfVersion   string   `json:"csrf_version,omitempty"`   // Example of including CSRF version in the output
	Tied          bool     `json:"tied,omitempty"`           // Example of including CSRF tied status in the output
	Authorization string   `header:"Authorization,omitempty"`
}

var DynamicProfileHandlerConfig = &core.APIConfiguration{
	SessionRequired: true,
	Allow:           []string{"guest_session", "user_session"},
	Permissions: rbac.Permissions{
		ReadOnlySessionData,
	},
	RequireCsrf: false, // keep the demo easy to call
}

var DynamicProfileInputRules = validation.FieldRules{
	"Email":      {Tags: "required,email"},
	"Age":        {Tags: "omitempty,gte=0,lte=120", Type: "int"},
	"Subscribed": {Tags: "required", Type: "bool", JSONName: "subscribed"},
}

var DynamicProfileOutputRules = validation.FieldRules{
	"Message":      {Tags: "required"},
	"SessionGroup": {Tags: "omitempty"},
	"ModeHeader":   {Tags: "required", Header: "X-Profile-Mode"},
}

// BasicActionHandler demonstrates a handler that processes input,
// potentially interacts with session state (here, it issues a new one),
// and returns a structured output.
func BasicActionHandler(input *ExampleInput, data *AppHandlerContext) (*ExampleOutput, *errors.AppError) {
	// For demonstration, we'll create a new, empty claims object.
	// In a real login handler, you would populate claims with user ID, roles, etc.
	// In other handlers, you might refresh existing claims or modify them.
	newSessionClaims := &core.SessionClaims{}
	newSessionClaims.SetClaim("session_data", "some_session_data")

	// Attempt to set/issue a new session cookie.
	// "Guest_session" is an example session mode/group.
	err := core.SetSessionCookie(
		data.Context,        // The request context (e.g., *gin.Context from core.Handler)
		data.SessionManager, // The session manager instance (from core.Handler)
		"guest_session",     // The desired session mode/group for the new cookie
		newSessionClaims,    // The claims for the new session
	)

	if err != nil {
		// If cookie issuance fails, return an internal server error.
		return nil, errors.NewInternalServerError("Failed to issue session cookie", err)
	}

	// Construct the response message.
	// data.HasSession refers to the state of the session *when this handler was invoked*,
	// before the new cookie might have been set by the call above.
	var incomingSessionStatus string
	if data.HasSession {
		incomingSessionStatus = "active"
	} else {
		incomingSessionStatus = "not active or not present"
	}

	resultMsg := fmt.Sprintf(
		"Processed queryParam: '%s'. Incoming session was %s. A new 'guest_session' cookie has been issued.",
		input.QueryParam,
		incomingSessionStatus,
	)

	var claims []string
	if data.HasSession && data.Claims != nil {
		for key, claim := range data.Claims.Claims {
			claims = append(claims, fmt.Sprintf("%s: %s", key, claim))
		}
	}

	authHeader, err := core.IssueCustomBearerToken(
		data.Context,
		data.SessionManager,
		"guest_session",
		newSessionClaims,
		&core.SessionAuthorizationConfiguration{
			Expiration: time.Minute * 5,
			VerifyTime: time.Second * 30,
		},
	)
	if err != nil {
		return nil, errors.NewInternalServerError("Failed to issue bearer token", err)
	}

	return &ExampleOutput{
		ResultMessage: resultMsg,
		CustomHeader:  "ActionProcessed-" + input.QueryParam,
		Claims:        claims,
		CsrfToken:     data.CsrfToken.Token,
		CsrfTokenTie:  data.CsrfToken.Tie,
		CsrfVersion:   data.CsrfToken.Version,
		Tied:          data.CsrfToken.Tied,
		Authorization: authHeader,
	}, nil
}

// AuthenticatedResourceHandlerConfig is a configuration that this time, strictly requires a session
var AuthenticatedResourceHandlerConfig = &core.APIConfiguration{
	SessionRequired: true,
	Allow:           []string{"guest_session", "user_session"},
	Permissions: rbac.Permissions{
		ReadWriteSessionData,
		ReadOnlySessionData,
	},
	RbacPolicy: rbac.PermissionsAndRole,
	Roles:      &[]string{"test", "test2"},
}

// AuthenticatedResourceOutput defines the output for a handler that exposes authenticated user/session data.
type AuthenticatedResourceOutput struct {
	SessionGroup       string   `json:"session_group,omitempty"`
	SessionExpiresAt   int64    `json:"session_expires_at,omitempty"`
	SessionRefreshesAt int64    `json:"session_refreshes_at,omitempty"`
	ResponseMessage    string   `json:"response_message"`
	Claims             []string `json:"claims,omitempty"` // Example of including claims in the output
}

// AuthenticatedResourceHandler demonstrates a handler that likely requires an active, valid session
// to access and return session-specific or user-specific data.
// For this handler to function as intended, the APIConfiguration for its route
// would typically have `SessionRequired=true` and likely `WorkspaceUser=true`.
func AuthenticatedResourceHandler(input *ExampleInput, data *AppHandlerContext) (*AuthenticatedResourceOutput, *errors.AppError) {
	// Assuming SessionRequired=true was set for this route, so data.HasSession should be true
	// and data.SessionHeader / data.Claims should be populated.
	// If SessionRequired=false, you'd need to handle the !data.HasSession case explicitly here
	// (e.g., return an unauthorized error or different content).

	output := &AuthenticatedResourceOutput{
		ResponseMessage: fmt.Sprintf("Authenticated access successful for query: '%s'.", input.QueryParam),
	}

	if data.SessionHeader != nil {
		output.SessionGroup = data.SessionGroup
		output.SessionExpiresAt = data.SessionHeader.LifetimeSec + data.SessionHeader.IssuedAt
		output.SessionRefreshesAt = data.SessionHeader.RefreshPeriodSec + data.SessionHeader.IssuedAt
	}

	if data.HasSession && data.Claims != nil {
		var claims []string
		for key, claim := range data.Claims.Claims {
			claims = append(claims, fmt.Sprintf("%s: %s", key, claim))
		}
		output.Claims = claims
	}

	return output, nil
}

var AuthenticatedEmptyResourceHandlerConfig = &core.APIConfiguration{
	SessionRequired: true,
	Allow:           []string{"guest_session", "user_session"},
	Permissions: rbac.Permissions{
		ReadWriteSessionData,
		ReadOnlySessionData,
	},
	RbacPolicy: rbac.PermissionsAndRole,
	Roles:      &[]string{"test", "test2"},
}

type AuthenticatedEmptyResourceOutput struct {
}

func AuthenticatedEmptyResourceHandler(input *ExampleInput, data *AppHandlerContext) (*AuthenticatedResourceOutput, *errors.AppError) {
	return &AuthenticatedResourceOutput{}, nil
}

func DynamicProfileHandler(input map[string]interface{}, data *AppHandlerContext) (map[string]any, *errors.AppError) {
	email, _ := input["Email"].(string)
	subscribed, _ := input["Subscribed"].(bool)

	var ageText string
	if age, ok := input["Age"]; ok {
		ageText = fmt.Sprintf(" Age: %v.", age)
	}

	message := fmt.Sprintf("Dynamic profile for %s created. Subscribed: %t.%s", email, subscribed, ageText)

	output := map[string]any{
		"Message":    message,
		"ModeHeader": "dynamic",
	}

	if data.SessionGroup != "" {
		output["SessionGroup"] = data.SessionGroup
	}

	return output, nil
}

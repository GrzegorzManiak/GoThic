package main

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/grzegorzmaniak/gothic/cache"
	"github.com/grzegorzmaniak/gothic/core"
	"github.com/grzegorzmaniak/gothic/helpers"
	"github.com/grzegorzmaniak/gothic/validation"
)

// AppSpecificBaseRoute would be a struct defined by the application developer,
// containing any base dependencies or configurations for their routes.
type AppSpecificBaseRoute struct {
	// Example: Database connections, logging instances, etc.
	AppName string
}

// the main function initializes the application, sets up routes, and starts the server.
func main() {

	// - You would typically load this from a secure location or environment variable.
	var sessionKey, _ = helpers.GenerateSymmetricKey(helpers.AESKeySize32)

	baseRoute := &AppSpecificBaseRoute{
		AppName: "MyApp",
	}

	mySessionManager := &AppSessionManager{
		SessionKeyValue:                   sessionKey,
		SessionAuthorizationConfiguration: &core.SessionAuthorizationConfiguration{CookieSecure: false},
		CsrfCookieData:                    &core.CsrfCookieData{Secure: false},
		RbacManager:                       &MyRbacManager{},
		Cache:                             cache.BuildDefaultCacheManager(nil),
	}

	router := gin.Default()
	validationEngine := validation.NewEngine(nil)
	routeCtor := core.NewRouteConstructor(router, baseRoute, mySessionManager, validationEngine)

	router.GET("/noAuth", func(ctx *gin.Context) {
		core.ExecuteRoute(ctx, baseRoute, BasicActionHandlerConfig, mySessionManager, validationEngine, BasicActionHandler)
	})

	// - Shorthand constructor version
	core.GET(routeCtor, "/auth", AuthenticatedResourceHandlerConfig, AuthenticatedResourceHandler)
	core.GET(routeCtor, "/authEmpty", AuthenticatedEmptyResourceHandlerConfig, AuthenticatedEmptyResourceHandler)
	router.POST("/dynamicProfile", func(ctx *gin.Context) {
		core.ExecuteDynamicRoute(
			ctx,
			baseRoute,
			DynamicProfileHandlerConfig,
			mySessionManager,
			validationEngine,
			"dynProfile:input",
			DynamicProfileInputRules,
			"dynProfile:output",
			DynamicProfileOutputRules,
			DynamicProfileHandler,
		)
	})

	httpAddr := fmt.Sprintf("%s:%s", "localhost", "8080")
	if err := router.Run(httpAddr); err != nil {
		fmt.Printf("Failed to start server: %v\n", err)
	}
}

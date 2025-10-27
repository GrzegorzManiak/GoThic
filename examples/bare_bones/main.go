package main

import (
	"fmt"

	"github.com/gin-gonic/gin"
	"github.com/grzegorzmaniak/gothic/cache"
	"github.com/grzegorzmaniak/gothic/core"
	"github.com/grzegorzmaniak/gothic/helpers"
)

// AppSpecificBaseRoute would be a struct defined by the application developer,
// containing any base dependencies or configurations for their routes.
type AppSpecificBaseRoute struct {
	// Example: Database connections, logging instances, etc.
	AppName string
}

// the main function initializes the application, sets up routes, and starts the server.
func main() {
	var sessionKey, _ = helpers.GenerateSymmetricKey(helpers.AESKeySize32)

	baseRoute := &AppSpecificBaseRoute{
		AppName: "MyApp",
	}

	mySessionManager := &AppSessionManager{
		SessionKeyValue:          sessionKey,
		SessionAuthorizationData: &core.SessionAuthorizationData{CookieSecure: false},
		CsrfCookieData:           &core.CsrfCookieData{Secure: false},
		Cache:                    cache.BuildDefaultCacheManager(nil),
	}

	router := gin.Default()
	router.GET("/noAuth", func(ctx *gin.Context) {
		core.ExecuteRoute(ctx, baseRoute, BasicActionHandlerConfig, mySessionManager, BasicActionHandler)
	})

	router.GET("/auth", func(ctx *gin.Context) {
		core.ExecuteRoute(ctx, baseRoute, AuthenticatedResourceHandlerConfig, mySessionManager, AuthenticatedResourceHandler)
	})

	httpAddr := fmt.Sprintf("%s:%s", "localhost", "8080")
	if err := router.Run(httpAddr); err != nil {
		fmt.Printf("Failed to start server: %v\n", err)
	}
}

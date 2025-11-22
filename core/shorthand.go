package core

import (
	"github.com/gin-gonic/gin"
	"github.com/grzegorzmaniak/gothic/errors"
	"github.com/grzegorzmaniak/gothic/helpers"
	"github.com/grzegorzmaniak/gothic/validation"
)

// RouteConstructor stores shared routing dependencies to avoid repeating them per registration.
type RouteConstructor[BaseRoute helpers.BaseRouteComponents] struct {
	router           *gin.Engine
	baseRoute        BaseRoute
	sessionManager   SessionManager
	validationEngine *validation.Engine
}

// NewRouteConstructor creates a new RouteConstructor. If validationEngine is nil, a default Engine is used.
func NewRouteConstructor[BaseRoute helpers.BaseRouteComponents](
	router *gin.Engine,
	baseRoute BaseRoute,
	sessionManager SessionManager,
	validationEngine *validation.Engine,
) *RouteConstructor[BaseRoute] {
	if validationEngine == nil {
		validationEngine = validation.NewEngine(nil)
	}

	return &RouteConstructor[BaseRoute]{
		router:           router,
		baseRoute:        baseRoute,
		sessionManager:   sessionManager,
		validationEngine: validationEngine,
	}
}

func registerRoute[InputType any, OutputType any, BaseRoute helpers.BaseRouteComponents](
	ctor *RouteConstructor[BaseRoute],
	method func(string, ...gin.HandlerFunc) gin.IRoutes,
	path string,
	sessionConfig *APIConfiguration,
	handlerFunc func(input *InputType, data *Handler[BaseRoute]) (*OutputType, *errors.AppError),
) {
	method(path, func(ctx *gin.Context) {
		ExecuteRoute(ctx, ctor.baseRoute, sessionConfig, ctor.sessionManager, ctor.validationEngine, handlerFunc)
	})
}

func GET[InputType any, OutputType any, BaseRoute helpers.BaseRouteComponents](
	ctor *RouteConstructor[BaseRoute],
	path string,
	sessionConfig *APIConfiguration,
	handlerFunc func(input *InputType, data *Handler[BaseRoute]) (*OutputType, *errors.AppError),
) {
	registerRoute(ctor, ctor.router.GET, path, sessionConfig, handlerFunc)
}

func POST[InputType any, OutputType any, BaseRoute helpers.BaseRouteComponents](
	ctor *RouteConstructor[BaseRoute],
	path string,
	sessionConfig *APIConfiguration,
	handlerFunc func(input *InputType, data *Handler[BaseRoute]) (*OutputType, *errors.AppError),
) {
	registerRoute(ctor, ctor.router.POST, path, sessionConfig, handlerFunc)
}

func PUT[InputType any, OutputType any, BaseRoute helpers.BaseRouteComponents](
	ctor *RouteConstructor[BaseRoute],
	path string,
	sessionConfig *APIConfiguration,
	handlerFunc func(input *InputType, data *Handler[BaseRoute]) (*OutputType, *errors.AppError),
) {
	registerRoute(ctor, ctor.router.PUT, path, sessionConfig, handlerFunc)
}

func DELETE[InputType any, OutputType any, BaseRoute helpers.BaseRouteComponents](
	ctor *RouteConstructor[BaseRoute],
	path string,
	sessionConfig *APIConfiguration,
	handlerFunc func(input *InputType, data *Handler[BaseRoute]) (*OutputType, *errors.AppError),
) {
	registerRoute(ctor, ctor.router.DELETE, path, sessionConfig, handlerFunc)
}

func PATCH[InputType any, OutputType any, BaseRoute helpers.BaseRouteComponents](
	ctor *RouteConstructor[BaseRoute],
	path string,
	sessionConfig *APIConfiguration,
	handlerFunc func(input *InputType, data *Handler[BaseRoute]) (*OutputType, *errors.AppError),
) {
	registerRoute(ctor, ctor.router.PATCH, path, sessionConfig, handlerFunc)
}

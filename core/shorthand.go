package core

import (
	"github.com/gin-gonic/gin"
	"github.com/grzegorzmaniak/gothic/errors"
	"github.com/grzegorzmaniak/gothic/helpers"
)

func GET[InputType any, OutputType any, BaseRoute helpers.BaseRouteComponents](
	router *gin.Engine,
	path string,
	baseRoute BaseRoute,
	sessionConfig *APIConfiguration,
	sessionManager SessionManager,
	handlerFunc func(input *InputType, data *Handler[BaseRoute]) (*OutputType, *errors.AppError),
) {
	router.GET(path, func(ctx *gin.Context) {
		ExecuteRoute(ctx, baseRoute, sessionConfig, sessionManager, handlerFunc)
	})
}

func POST[InputType any, OutputType any, BaseRoute helpers.BaseRouteComponents](
	router *gin.Engine,
	path string,
	baseRoute BaseRoute,
	sessionConfig *APIConfiguration,
	sessionManager SessionManager,
	handlerFunc func(input *InputType, data *Handler[BaseRoute]) (*OutputType, *errors.AppError),
) {
	router.POST(path, func(ctx *gin.Context) {
		ExecuteRoute(ctx, baseRoute, sessionConfig, sessionManager, handlerFunc)
	})
}

func PUT[InputType any, OutputType any, BaseRoute helpers.BaseRouteComponents](
	router *gin.Engine,
	path string,
	baseRoute BaseRoute,
	sessionConfig *APIConfiguration,
	sessionManager SessionManager,
	handlerFunc func(input *InputType, data *Handler[BaseRoute]) (*OutputType, *errors.AppError),
) {
	router.PUT(path, func(ctx *gin.Context) {
		ExecuteRoute(ctx, baseRoute, sessionConfig, sessionManager, handlerFunc)
	})
}

func DELETE[InputType any, OutputType any, BaseRoute helpers.BaseRouteComponents](
	router *gin.Engine,
	path string,
	baseRoute BaseRoute,
	sessionConfig *APIConfiguration,
	sessionManager SessionManager,
	handlerFunc func(input *InputType, data *Handler[BaseRoute]) (*OutputType, *errors.AppError),
) {
	router.DELETE(path, func(ctx *gin.Context) {
		ExecuteRoute(ctx, baseRoute, sessionConfig, sessionManager, handlerFunc)
	})
}

func PATCH[InputType any, OutputType any, BaseRoute helpers.BaseRouteComponents](
	router *gin.Engine,
	path string,
	baseRoute BaseRoute,
	sessionConfig *APIConfiguration,
	sessionManager SessionManager,
	handlerFunc func(input *InputType, data *Handler[BaseRoute]) (*OutputType, *errors.AppError),
) {
	router.PATCH(path, func(ctx *gin.Context) {
		ExecuteRoute(ctx, baseRoute, sessionConfig, sessionManager, handlerFunc)
	})
}

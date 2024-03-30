package handler

import (
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

type handler struct {
	handler *gin.Engine
	service service
}

var (
	PORT                = os.Getenv("AUTH_SERVER_PORT") // порт на котором работает http сервер
	SUPER_USER          = os.Getenv("AUTH_SERVER_SUPER_USER")
	SUPER_USER_PASSWORD = os.Getenv("AUTH_SERVER_SUPER_USER_PASSWORD")
)

type service interface {
	Generate(ttl int64) (string, error)
	Validate(tokenValidating string) (bool, error)
}

func New(service service) *handler {
	return &handler{handler: gin.Default(), service: service}
}

func (h *handler) Run() {
	h.handler.Group("/generate").Use(gin.BasicAuth(gin.Accounts{
		SUPER_USER: SUPER_USER_PASSWORD,
	})).GET("/:ttl", h.generateToken)

	h.handler.GET("/check", h.checkToken)

	if PORT == "" {
		PORT = "8000"
	}
	httpServer := &http.Server{
		Addr:    ":" + PORT,
		Handler: h.handler,
	}
	httpServer.ListenAndServe()
}

func (h *handler) generateToken(c *gin.Context) {
	ttl, err := strconv.ParseInt(c.Param("ttl"), 0, 64)
	if err != nil {
		c.AbortWithStatusJSON(
			http.StatusBadRequest,
			map[string]string{
				"details": err.Error(),
				"status":  "ERROR"},
		)
		return
	}

	token, err := h.service.Generate(ttl)
	if err != nil {
		c.AbortWithStatusJSON(
			http.StatusInternalServerError,
			map[string]string{
				"details": err.Error(),
				"status":  "ERROR"},
		)
		return
	}

	c.JSON(http.StatusOK, map[string]string{"access_token": token})
}

func (h *handler) checkToken(c *gin.Context) {
	header := Header{}
	if err := c.ShouldBindHeader(&header); err != nil {
		c.AbortWithStatusJSON(
			http.StatusUnauthorized,
			map[string]string{
				"details": err.Error(),
				"status":  "ERROR"},
		)
		return
	}
	accessToken := strings.Replace(header.Authorization, "Bearer ", "", -1)

	check, err := h.service.Validate(accessToken)
	if err != nil {
		c.AbortWithStatusJSON(
			http.StatusUnauthorized,
			map[string]string{
				"details": err.Error(),
				"status":  "ERROR"},
		)
		return
	}
	status := http.StatusOK
	if !check {
		status = http.StatusUnauthorized
	}

	c.JSON(status, map[string]interface{}{"authorized": check})
}

type Header struct {
	Authorization string
}

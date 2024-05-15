package ssojwt

import (
	"github.com/gin-gonic/gin"
)

func SetupRouter(config SSOConfig) *gin.Engine {
	r := gin.Default()
	r.GET("/", func(c *gin.Context) {
		c.String(200, "hello")
	})

	accessTokenMiddleware := MakeAccessTokenMiddleware(config, "user")

	r.GET("/login", LoginCreator(config, nil))
	r.GET("/logout", Logout(config, nil))
	r.GET("/check", accessTokenMiddleware, CheckUserData(nil))
	r.GET("/refresh", MakeRefreshTokenMiddleware(config))

	return r
}

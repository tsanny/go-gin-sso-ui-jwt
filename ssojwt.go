package ssojwt

import (
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

type SSOConfig struct {
	AccessTokenExpireTime  time.Duration
	RefreshTokenExpireTime time.Duration
	AccessTokenSecretKey   string
	RefreshTokenSecretKey  string
	ServiceUrl             string
	OriginUrl              string
	CasURL                 string
	SuccessSSOAuthRedirect string
	RedirectToFrontend     bool
}

func MakeSSOConfig(accessTokenExpireTime, refreshTokenExpireTime time.Duration, accessTokenSecretKey, refreshTokenSecretKey, serviceUrl, originUrl, successSSOAuthRedirect string, redirectToFrontend bool) SSOConfig {
	return SSOConfig{
		AccessTokenExpireTime:  accessTokenExpireTime,
		RefreshTokenExpireTime: refreshTokenExpireTime,
		AccessTokenSecretKey:   accessTokenSecretKey,
		RefreshTokenSecretKey:  refreshTokenSecretKey,
		ServiceUrl:             serviceUrl,
		OriginUrl:              originUrl,
		CasURL:                 "https://sso.ui.ac.id/cas2/",
		SuccessSSOAuthRedirect: successSSOAuthRedirect,
		RedirectToFrontend:     redirectToFrontend,
	}
}

func LoginCreator(config SSOConfig, errorLogger *log.Logger) gin.HandlerFunc {
	if errorLogger == nil {
		errorLogger = log.New(io.Discard, "Error: ", log.Ldate|log.Ltime)
	}

	return func(c *gin.Context) {
		ticket := c.Request.URL.Query().Get("ticket")
		res, err := LoginRequestHandler(ticket, config)
		if err != nil {
			errorLogger.Printf("error in parsing sso request: %v", err)
			c.AbortWithStatus(http.StatusInternalServerError)
			return
		}

		if res.User == "" {
			redirectURL := (config.CasURL + "login?service=" + url.QueryEscape(config.ServiceUrl))
			c.Redirect(http.StatusTemporaryRedirect, redirectURL)
			return
		}

		if config.RedirectToFrontend {
			redirectURL := (config.SuccessSSOAuthRedirect + "?token=" + res.AccessToken)
			c.Redirect(http.StatusTemporaryRedirect, redirectURL)
			return
		}

		c.JSON(http.StatusOK, res)
		return
	}
}

func Logout(config SSOConfig, errorLogger *log.Logger) gin.HandlerFunc {
	if errorLogger == nil {
		errorLogger = log.New(io.Discard, "Error: ", log.Ldate|log.Ltime)
	}

	return func(c *gin.Context) {
		destination := config.ServiceUrl
		if config.RedirectToFrontend {
			destination = config.SuccessSSOAuthRedirect
		}
		redirectURL := (config.CasURL + "logout?url=" + url.QueryEscape(destination))
		c.Redirect(http.StatusTemporaryRedirect, redirectURL)
		return
	}
}

func CheckUserData(errorLogger *log.Logger) gin.HandlerFunc {
	if errorLogger == nil {
		errorLogger = log.New(io.Discard, "Error: ", log.Ldate|log.Ltime)
	}

	return func(c *gin.Context) {
		data := c.Value("user")
		if data == nil {
			data = jwt.MapClaims{"npm": "none"}
		}
		c.JSON(http.StatusOK, data)
	}
}

func GetRefreshToken(config SSOConfig, errorLogger *log.Logger) gin.HandlerFunc {
	if errorLogger == nil {
		errorLogger = log.New(io.Discard, "Error: ", log.Ldate|log.Ltime)
	}

	return func(c *gin.Context) {
		refresh := MakeRefreshTokenMiddleware(config)
		c.JSON(http.StatusOK, refresh)
	}
}

func LoginRequestHandler(ticket string, config SSOConfig) (res LoginResponse, err error) {
	bodyBytes, err := ValidateTicket(config, ticket)
	if err != nil {
		err = fmt.Errorf("error when cheking ticket: %w", err)
		return
	}

	model, err := Unmarshal(bodyBytes)
	if err != nil {
		err = fmt.Errorf("error in unmarshaling: %w", err)
		return
	}

	res, err = MakeLoginResponse(config, model)
	if err != nil {
		err = fmt.Errorf("error in creating token: %w", err)
	}
	return
}

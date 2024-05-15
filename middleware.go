package ssojwt

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

func MakeAccessTokenMiddleware(config SSOConfig, key string) gin.HandlerFunc {
	return func(c *gin.Context) {
		authorization := c.GetHeader("Authorization")
		AuthorizationMap := strings.Split(authorization, " ")
		if len(AuthorizationMap) != 2 {
			c.JSON(http.StatusUnauthorized, gin.H{"status": 401, "error": "invalid_token"})
			c.Abort()
			return
		}
		tokenString := AuthorizationMap[1]
		token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
			return []byte(config.AccessTokenSecretKey), nil
		})
		if err != nil {
			if err.Error() == "Token is expired" {
				c.JSON(http.StatusUnauthorized, gin.H{"status": 401, "error": "expired_token"})
				c.Abort()
			} else {
				c.JSON(http.StatusUnauthorized, gin.H{"status": 401, "error": "invalid_token"})
				c.Abort()
			}
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if ok && token.Valid {
			c.Set(key, claims)
		}
	}
}

func MakeRefreshTokenMiddleware(config SSOConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		authorization := c.Request.Header.Get("Authorization")
		AuthorizationMap := strings.Split(authorization, " ")
		if len(AuthorizationMap) != 2 {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}
		tokenString := AuthorizationMap[1]
		token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
			return []byte(config.RefreshTokenSecretKey), nil
		})
		if err != nil {
			c.AbortWithStatus(http.StatusUnauthorized)
			return
		}

		claims, ok := token.Claims.(jwt.MapClaims)
		if ok && token.Valid {
			jurusan := claims["jurusan"].(map[string]interface{})

			newClaims := ServiceResponse{
				AuthenticationSuccess: AuthenticationSuccess{
					User: claims["user"].(string),
					Attributes: Attributes{
						Nama: claims["nama"].(string),
						Npm:  claims["npm"].(string),
						Jurusan: Jurusan{
							Faculty:      jurusan["faculty"].(string),
							ShortFaculty: jurusan["shortFaculty"].(string),
							Major:        jurusan["major"].(string),
							Program:      jurusan["program"].(string),
						},
					},
				},
			}

			accessToken, err := CreateAccessToken(config, newClaims)
			if err != nil {
				c.AbortWithStatus(http.StatusInternalServerError)
				return
			}

			refreshToken, err := CreateRefreshToken(config, newClaims)
			if err != nil {
				c.AbortWithStatus(http.StatusInternalServerError)
				return
			}

			res := LoginResponse{
				AccessToken:  accessToken,
				RefreshToken: refreshToken,
				Fakultas:     nil,
			}

			c.JSON(http.StatusOK, res)
			return
		}
		c.AbortWithStatus(http.StatusUnauthorized)
	}
}

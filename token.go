package ssojwt

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

type SSOJwtClaim struct {
	Nama         string  `json:"nama"`
	User         string  `json:"user"`
	Npm          string  `json:"npm"`
	Jurusan      Jurusan `json:"jurusan"`
	IsAdmin      bool    `json:"is_admin"`
	IsSuperAdmin bool    `json:"is_super_admin"`
	jwt.RegisteredClaims
}

func CreateAccessToken(config SSOConfig, ssoResponse ServiceResponse) (token string, err error) {
	RegisteredClaims := jwt.RegisteredClaims{}
	if config.AccessTokenExpireTime != 0 {
		RegisteredClaims = jwt.RegisteredClaims{
			ExpiresAt: &jwt.NumericDate{Time: time.Now().Add(config.AccessTokenExpireTime)},
		}
	}

	claims := &SSOJwtClaim{
		Nama:             ssoResponse.AuthenticationSuccess.Attributes.Nama,
		User:             ssoResponse.AuthenticationSuccess.User,
		Npm:              ssoResponse.AuthenticationSuccess.Attributes.Npm,
		Jurusan:          ssoResponse.AuthenticationSuccess.Attributes.Jurusan,
		IsAdmin:          ssoResponse.AuthenticationSuccess.Attributes.IsAdmin,
		IsSuperAdmin:     ssoResponse.AuthenticationSuccess.Attributes.IsSuperAdmin,
		RegisteredClaims: RegisteredClaims,
	}

	rawToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token, err = rawToken.SignedString([]byte(config.AccessTokenSecretKey))
	if err != nil {
		err = fmt.Errorf("token signing error: %w", err)
	}
	return
}

func CreateRefreshToken(config SSOConfig, ssoResponse ServiceResponse) (token string, err error) {
	RegisteredClaims := jwt.RegisteredClaims{}
	if config.RefreshTokenExpireTime != 0 {
		RegisteredClaims = jwt.RegisteredClaims{
			ExpiresAt: &jwt.NumericDate{Time: time.Now().Add(config.RefreshTokenExpireTime)},
		}
	}

	claims := &SSOJwtClaim{
		Nama:             ssoResponse.AuthenticationSuccess.Attributes.Nama,
		User:             ssoResponse.AuthenticationSuccess.User,
		Npm:              ssoResponse.AuthenticationSuccess.Attributes.Npm,
		Jurusan:          ssoResponse.AuthenticationSuccess.Attributes.Jurusan,
		IsAdmin:          ssoResponse.AuthenticationSuccess.Attributes.IsAdmin,
		IsSuperAdmin:     ssoResponse.AuthenticationSuccess.Attributes.IsSuperAdmin,
		RegisteredClaims: RegisteredClaims,
	}

	rawToken := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	token, err = rawToken.SignedString([]byte(config.RefreshTokenSecretKey))
	if err != nil {
		err = fmt.Errorf("token signing error: %w", err)
	}
	return
}

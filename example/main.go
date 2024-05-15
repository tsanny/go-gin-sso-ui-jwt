package main

import (
	ssojwt "github.com/tsanny/go-gin-sso-ui-jwt"
	"time"
)

func main() {
	AccessTokenSecretKey := "oogabooga"
	RefreshTokenSecretKey := "fizzbuzz"
	AppURL := "http://localhost:8080"
	FrontendAppURL := "http://localhost:3000"
	RedirectToFrontend := false

	ssoConfig := ssojwt.MakeSSOConfig(
		time.Hour*168,
		time.Hour*720,
		AccessTokenSecretKey,
		RefreshTokenSecretKey,
		AppURL+"/login",
		AppURL+"/",
		FrontendAppURL,
		RedirectToFrontend,
	)

	r := ssojwt.SetupRouter(ssoConfig)

	err := r.Run()
	if err != nil {
		panic("Failed starting the router: " + err.Error())
	}
}

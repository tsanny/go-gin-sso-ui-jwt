package ssojwt

type LoginResponse struct {
	AccessToken  string   `json:"access_token"`
	RefreshToken string   `json:"refresh_token"`
	User         string   `json:"user,omitempty"`
	Nama         string   `json:"nama,omitempty"`
	Npm          string   `json:"npm,omitempty"`
	Fakultas     *Jurusan `json:"fakultas,omitempty"`
}

func MakeLoginResponse(config SSOConfig, model ServiceResponse) (res LoginResponse, err error) {
	accessToken, err := CreateAccessToken(config, model)
	if err != nil {
		return
	}
	refreshToken, err := CreateRefreshToken(config, model)
	if err != nil {
		return
	}

	res = LoginResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		User:         model.AuthenticationSuccess.User,
		Nama:         model.AuthenticationSuccess.Attributes.Nama,
		Npm:          model.AuthenticationSuccess.Attributes.Npm,
		Fakultas:     &model.AuthenticationSuccess.Attributes.Jurusan,
	}
	return
}

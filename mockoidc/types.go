package mockoidc

import "errors"

type Endpoints struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	JWKSURI                           string   `json:"jwks_uri"`
	UserInfoEndpoint                  string   `json:"userinfo_endpoint"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ClaimsParameterSupported          bool     `json:"claims_parameter_supported"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ClaimsSupported                   []string `json:"claims_supported"`
	ClaimTypesSupported               []string `json:"claim_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported"`
}

type Tokens struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

type User struct {
	ID     string   `json:"id"`
	Claims []*Claim `json:"claims"`
}

type Client struct {
	ID     string `json:"id"`
	Secret string `json:"secret"`
}

type Claim struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Login struct {
	Aud         string `json:"aud,omitempty"`
	Sub         string `json:"sub,omitempty"`
	AuthTime    int64  `json:"auth_time,omitempty"` //for claim auth_time
	RedirectURI string `json:"redirect_uri,omitempty"`
	State       string `json:"state,omitempty"`
	UserID      string `json:"user_id,omitempty"`
}

type Error struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

var ErrNotFound = errors.New("not found")

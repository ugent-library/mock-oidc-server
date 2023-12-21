package main

import "time"

type providerEndpoints struct {
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

type tokens struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

type User struct {
	Username string
	Claims   []*Claim
}

type Client struct {
	ID     string
	Secret string
}

type Claim struct {
	Name  string
	Value string
}

type Login struct {
	Aud         string
	Sub         string
	AuthTime    *time.Time //for claim auth_time
	RedirectURI string
	State       string
	User        *User
}

type OIDCError struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"`
}

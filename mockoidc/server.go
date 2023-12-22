package mockoidc

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/bluele/gcache"
	"github.com/golang-jwt/jwt/v5"
	"github.com/gorilla/sessions"
	"github.com/oklog/ulid/v2"
	"go.uber.org/zap"
	"gopkg.in/square/go-jose.v2"
)

type Config struct {
	SessionCookieName string
	SessionSecret     string
	URIBase           string
	ExpiresIn         time.Duration
	PublicKey         *rsa.PublicKey
	PrivateKey        *rsa.PrivateKey
	Logger            *zap.SugaredLogger
	Users             []*User
	Clients           []*Client
}

type Server struct {
	keyID             string
	logger            *zap.SugaredLogger
	sessionCookieName string
	sessionStore      *sessions.CookieStore
	publicKey         *rsa.PublicKey
	privateKey        *rsa.PrivateKey
	endpoints         *Endpoints
	logins            gcache.Cache
	expiresIn         time.Duration
	uriBase           string
	users             []*User
	clients           []*Client
}

func NewServer(config Config) (*Server, error) {
	uriBase, err := url.Parse(config.URIBase)
	if err != nil {
		return nil, err
	}

	sessionStore := sessions.NewCookieStore([]byte(config.SessionSecret))
	sessionStore.MaxAge(int(config.ExpiresIn))
	sessionStore.Options.Path = uriBase.Path + "/auth"
	sessionStore.Options.HttpOnly = true
	sessionStore.Options.Secure = false

	endpoints := &Endpoints{
		Issuer:                config.URIBase,
		AuthorizationEndpoint: config.URIBase + "/auth",
		TokenEndpoint:         config.URIBase + "/token",
		JWKSURI:               config.URIBase + "/certs",
		UserInfoEndpoint:      config.URIBase + "/userinfo",
		TokenEndpointAuthMethodsSupported: []string{
			"client_secret_post",
		},
		GrantTypesSupported: []string{
			"authorization_code",
		},
		ResponseTypesSupported:   []string{"code"},
		ClaimsParameterSupported: false,
		ScopesSupported: []string{
			"openid",
			"profile",
			"email",
		},
		ClaimsSupported: []string{
			"aud",
			"sub",
			"iss",
			"auth_time",
			"name",
			"given_name",
			"family_name",
			"preferred_username",
			"email",
		},
		ClaimTypesSupported:              []string{"normal"},
		IDTokenSigningAlgValuesSupported: []string{"RS256"},
	}

	return &Server{
		endpoints:         endpoints,
		publicKey:         config.PublicKey,
		privateKey:        config.PrivateKey,
		uriBase:           config.URIBase,
		keyID:             ulid.Make().String(),
		logger:            config.Logger,
		sessionCookieName: config.SessionCookieName,
		sessionStore:      sessionStore,
		expiresIn:         config.ExpiresIn,
		users:             config.Users,
		clients:           config.Clients,
		logins:            gcache.New(100).LRU().Expiration(config.ExpiresIn).Build(),
	}, nil
}

func (s *Server) sendOIDCError(w http.ResponseWriter, statusCode int, err string, errDesc string) {
	data, _ := json.Marshal(Error{
		Error:            err,
		ErrorDescription: errDesc,
	})
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	w.Write(data)
}

func (s *Server) AuthGet(w http.ResponseWriter, r *http.Request) {
	session, _ := s.sessionStore.Get(r, s.sessionCookieName)

	params := r.URL.Query()
	responseType := params.Get("response_type")
	state := params.Get("state")
	redirectURI := params.Get("redirect_uri")
	scope := params.Get("scope")
	clientID := params.Get("client_id")

	redirectTo, err := url.ParseRequestURI(redirectURI)
	if err != nil {
		http.Error(w, "unable to parse parameter redirect_uri", http.StatusBadRequest)
		return
	}

	if oldCode, ok := session.Values["code"]; ok {
		q := redirectTo.Query()
		if state != "" {
			q.Set("state", state)
		}
		q.Set("code", oldCode.(string))
		q.Set("iss", s.endpoints.Issuer)
		redirectTo.RawQuery = q.Encode()
		http.Redirect(w, r, redirectTo.String(), http.StatusFound)
		return
	}

	var oidcError *Error

	if responseType != "code" {
		oidcError = &Error{Error: "unsupported_response_type", ErrorDescription: "response_type must be code"}
	} else if s.GetClient(clientID) == nil {
		oidcError = &Error{Error: "unauthorized_client", ErrorDescription: "unknown client_id"}
	} else {
		requestedScopes := strings.Split(scope, " ")
		for i := 0; i < len(requestedScopes); i++ {
			requestedScopes[i] = strings.TrimSpace(requestedScopes[i])
		}
		for _, rs := range requestedScopes {
			if !slices.Contains(s.endpoints.ScopesSupported, rs) {
				oidcError = &Error{
					Error:            "invalid_scope",
					ErrorDescription: "invalid scope " + rs,
				}
				break
			}
		}
	}

	if oidcError != nil {
		q := redirectTo.Query()
		q.Set("error", oidcError.Error)
		q.Set("error_description", oidcError.ErrorDescription)
		redirectTo.RawQuery = q.Encode()
		http.Redirect(w, r, redirectTo.String(), http.StatusFound)
		return
	}

	templateAuth.Execute(w, templateAuthParams{
		FormAction:   "/auth",
		Scope:        scope,
		RedirectURI:  redirectURI,
		State:        state,
		ClientID:     clientID,
		ResponseType: responseType,
	})
}

func (s *Server) AuthPost(w http.ResponseWriter, r *http.Request) {
	session, _ := s.sessionStore.Get(r, s.sessionCookieName)
	r.ParseForm()

	params := r.PostForm

	username := params.Get("username")
	responseType := params.Get("response_type")
	state := params.Get("state")
	redirectURI := params.Get("redirect_uri")
	scope := params.Get("scope")
	clientID := params.Get("client_id")

	redirectTo, err := url.ParseRequestURI(redirectURI)
	if err != nil {
		http.Error(w, "unable to parse parameter redirect_uri", http.StatusBadRequest)
		return
	}

	var oidcError *Error

	if responseType != "code" {
		oidcError = &Error{Error: "unsupported_response_type", ErrorDescription: "response_type must be code"}
	} else if s.GetClient(clientID) == nil {
		oidcError = &Error{Error: "unauthorized_client", ErrorDescription: "unknown client_id"}
	} else {
		requestedScopes := strings.Split(scope, " ")
		for i := 0; i < len(requestedScopes); i++ {
			requestedScopes[i] = strings.TrimSpace(requestedScopes[i])
		}
		for _, rs := range requestedScopes {
			if !slices.Contains(s.endpoints.ScopesSupported, rs) {
				oidcError = &Error{
					Error:            "invalid_scope",
					ErrorDescription: "invalid scope " + rs,
				}
				break
			}
		}
	}

	if oidcError != nil {
		q := redirectTo.Query()
		q.Set("error", oidcError.Error)
		q.Set("error_description", oidcError.ErrorDescription)
		redirectTo.RawQuery = q.Encode()
		http.Redirect(w, r, redirectTo.String(), http.StatusFound)
		return
	}

	var authError string

	if username != "" {
		var user *User = s.GetUser(username)
		if user == nil {
			authError = "Unable to find user " + username
		} else {
			code := ulid.Make().String()
			session.Values["code"] = code
			if err := s.sessionStore.Save(r, w, session); err != nil {
				s.logger.Errorf("unable to save session: %s", err)
				http.Error(w, "unexpected error", http.StatusInternalServerError)
				return
			}
			now := time.Now()
			newLogin := &Login{
				Aud:         clientID,
				Sub:         ulid.Make().String(),
				RedirectURI: redirectURI,
				User:        user,
				AuthTime:    &now,
				State:       state,
			}
			if err := s.logins.Set(code, newLogin); err != nil {
				s.logger.Errorf("unable to store mapping code to user: %s", err)
				http.Error(w, "unexpected error", http.StatusInternalServerError)
				return
			}
			q := redirectTo.Query()
			if state != "" {
				q.Set("state", state)
			}
			q.Set("iss", s.endpoints.Issuer)
			q.Set("code", code)
			redirectTo.RawQuery = q.Encode()
			http.Redirect(w, r, redirectTo.String(), http.StatusFound)
			return
		}
	}

	templateAuth.Execute(w, templateAuthParams{
		FormAction:   "/auth",
		Error:        authError,
		Scope:        scope,
		RedirectURI:  redirectURI,
		State:        state,
		ClientID:     clientID,
		ResponseType: responseType,
	})
}

func (s *Server) loginToClaims(login *Login) jwt.MapClaims {
	claims := jwt.MapClaims{}
	for _, c := range login.User.Claims {
		claims[c.Name] = c.Value
	}
	claims["iss"] = s.endpoints.Issuer
	claims["sub"] = login.Sub
	claims["aud"] = login.Aud
	claims["auth_time"] = login.AuthTime.Unix()
	claims["iat"] = time.Now().Unix()
	claims["exp"] = time.Now().Add(s.expiresIn).Unix()
	return claims
}

func (s *Server) Token(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.sendOIDCError(w, http.StatusBadRequest, "invalid_request", "invalid_request")
		return
	}

	params := r.PostForm

	redirectURI := params.Get("redirect_uri")
	code := params.Get("code")
	grantType := params.Get("grant_type")
	clientID := params.Get("client_id")
	clientSecret := params.Get("client_secret")

	if redirectURI == "" || code == "" || grantType != "authorization_code" || clientID == "" || clientSecret == "" {
		s.sendOIDCError(w, http.StatusBadRequest, "invalid_request", "invalid_request")
		return
	}

	client := s.GetClient(clientID)
	if client == nil || client.Secret != clientSecret {
		s.sendOIDCError(w, http.StatusUnauthorized, "invalid_client", "invalid_client")
		return
	}

	l, err := s.logins.Get(code)
	if errors.Is(err, gcache.KeyNotFoundError) {
		s.sendOIDCError(w, http.StatusBadRequest, "invalid_grant", "invalid_grant")
		return
	} else if err != nil {
		s.logger.Errorf("unable to fetch login from store: %s", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	login := l.(*Login)
	if login.RedirectURI != redirectURI {
		s.sendOIDCError(w, http.StatusBadRequest, "invalid_grant", "invalid_grant")
		return
	}

	//ALL OK
	claims := s.loginToClaims(login)

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	// NOTE: This is important as the library matches this keyID with the public key
	token.Header["kid"] = s.keyID
	idToken, err := token.SignedString(s.privateKey)
	if err != nil {
		s.logger.Errorf("unable to sign jwt token: %s", err)
		s.sendOIDCError(w, http.StatusInternalServerError, "server_errror", "server_error")
		return
	}
	t := &Tokens{
		TokenType:   "Bearer",
		IDToken:     idToken,
		AccessToken: code,
		ExpiresIn:   int(s.expiresIn.Seconds()),
	}
	data, _ := json.Marshal(t)
	w.Header().Add("Content-Type", "application/json")
	w.Header().Add("Cache-Control", "no-store")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

func (s *Server) UserInfo(w http.ResponseWriter, r *http.Request) {
	accessToken := strings.TrimSpace(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))

	var statusCode int
	var data []byte = []byte{}

	if accessToken == "" {
		statusCode = http.StatusUnauthorized
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("WWW-Authenticate", "Bearer")
		data = []byte("unauthorized")
	} else if l, err := s.logins.Get(accessToken); err != nil {
		if errors.Is(err, gcache.KeyNotFoundError) {
			statusCode = http.StatusUnauthorized
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("WWW-Authenticate", "Bearer error=\"unsufficient_scope\"")
			data = []byte("unauthorized")
		} else {
			statusCode = http.StatusInternalServerError
			w.Header().Set("Content-Type", "text/plain")
			data = []byte("internal_server_error")
		}
	} else {
		statusCode = http.StatusOK
		w.Header().Add("Content-Type", "application/json")
		login := l.(*Login)
		data, _ = json.Marshal(login.User.Claims)
	}

	w.WriteHeader(statusCode)
	w.Write(data)
}

func (s *Server) Certs(w http.ResponseWriter, r *http.Request) {
	jwk := jose.JSONWebKey{
		Key:       s.publicKey,
		KeyID:     s.keyID,
		Use:       "sig",
		Algorithm: "RS256",
	}

	jwks := jose.JSONWebKeySet{
		Keys: []jose.JSONWebKey{jwk},
	}
	data, _ := json.Marshal(jwks)

	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

func (s *Server) Discovery(w http.ResponseWriter, r *http.Request) {
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	data, _ := json.Marshal(s.endpoints)
	w.Write(data)
}

func (s *Server) Clear(w http.ResponseWriter, r *http.Request) {
	s.logins.Purge()
	w.Header().Add("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func (s *Server) GetClient(id string) *Client {
	for _, client := range s.clients {
		if client.ID == id {
			return client
		}
	}
	return nil
}

func (s *Server) GetUser(username string) *User {
	for _, user := range s.users {
		if user.Username == username {
			return user
		}
	}
	return nil
}

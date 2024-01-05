package mockoidc

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

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
	Store             *TokenStore
}

type Server struct {
	keyID             string
	logger            *zap.SugaredLogger
	sessionCookieName string
	sessionStore      *sessions.CookieStore
	publicKey         *rsa.PublicKey
	privateKey        *rsa.PrivateKey
	endpoints         *Endpoints
	tokens            *TokenStore
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
		tokens:            config.Store,
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
	prompt := params.Get("prompt")

	redirectTo, err := url.ParseRequestURI(redirectURI)
	if err != nil {
		http.Error(w, "unable to parse parameter redirect_uri", http.StatusBadRequest)
		return
	}

	sessionID := "" // session.ID for CookieStore is always empty
	if s, ok := session.Values["id"]; ok {
		sessionID = s.(string)
	}
	token, _ := s.tokens.GetTokenBySession(sessionID, clientID, redirectURI)
	if token != nil && slices.Contains([]string{"login", "select_account"}, prompt) {
		s.tokens.RemoveToken(token)
		token = nil
	}
	if token != nil {
		q := redirectTo.Query()
		if state != "" {
			q.Set("state", state)
		}
		q.Set("code", token.Code)
		q.Set("iss", s.endpoints.Issuer)
		redirectTo.RawQuery = q.Encode()
		http.Redirect(w, r, redirectTo.String(), http.StatusFound)
		return
	}

	var oidcError *Error

	if responseType != "code" {
		oidcError = &Error{Error: "unsupported_response_type", ErrorDescription: "response_type must be code"}
	} else if s.getClient(clientID) == nil {
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

	buf := &bytes.Buffer{}
	err = templateAuth.Execute(buf, templateAuthParams{
		Scope:        scope,
		RedirectURI:  redirectURI,
		State:        state,
		ClientID:     clientID,
		ResponseType: responseType,
		Users:        s.users,
	})
	if err != nil {
		s.logger.Errorf("template error: %s", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(buf.Bytes())
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
	} else if s.getClient(clientID) == nil {
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
		var user *User = s.getUser(username)
		if user == nil {
			authError = "Unable to find user " + username
		} else {
			sessionID := newSessionID()
			session.Values["id"] = sessionID
			if err := s.sessionStore.Save(r, w, session); err != nil {
				s.logger.Errorf("unable to save session: %s", err)
				http.Error(w, "unexpected error", http.StatusInternalServerError)
				return
			}
			token := s.tokens.NewToken(sessionID, clientID, redirectURI)
			token.UserID = user.ID

			if err := s.tokens.AddToken(token); err != nil {
				s.logger.Errorf("unable to store mapping code to user: %s", err)
				http.Error(w, "unexpected error", http.StatusInternalServerError)
				return
			}
			q := redirectTo.Query()
			if state != "" {
				q.Set("state", state)
			}
			q.Set("iss", s.endpoints.Issuer)
			q.Set("code", token.Code)
			redirectTo.RawQuery = q.Encode()
			http.Redirect(w, r, redirectTo.String(), http.StatusFound)
			return
		}
	}

	buf := &bytes.Buffer{}
	templateAuth.Execute(buf, templateAuthParams{
		Error:        authError,
		Scope:        scope,
		RedirectURI:  redirectURI,
		State:        state,
		ClientID:     clientID,
		ResponseType: responseType,
		Users:        s.users,
	})
	if err != nil {
		s.logger.Errorf("template error: %s", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusOK)
	w.Write(buf.Bytes())
}

func (s *Server) tokenToClaims(token *Token) jwt.MapClaims {
	claims := jwt.MapClaims{}
	user := s.getUser(token.UserID)
	for _, c := range user.Claims {
		claims[c.Name] = c.Value
	}
	claims["iss"] = s.endpoints.Issuer
	claims["sub"] = token.Sub
	claims["aud"] = token.Aud
	claims["auth_time"] = token.AuthTime
	claims["iat"] = token.Iat
	claims["exp"] = token.Exp
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

	client := s.getClient(clientID)
	if client == nil || client.Secret != clientSecret {
		s.sendOIDCError(w, http.StatusUnauthorized, "invalid_client", "invalid_client")
		return
	}

	token, err := s.tokens.GetTokenByCode(code, clientID, redirectURI)
	if errors.Is(err, ErrNotFound) {
		s.sendOIDCError(w, http.StatusBadRequest, "invalid_grant", "invalid_grant")
		return
	} else if err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	if token, err = s.tokens.ExposeToken(token); err != nil {
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	claims := s.tokenToClaims(token)

	signedToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	// NOTE: This is important as the library matches this keyID with the public key
	signedToken.Header["kid"] = s.keyID
	idToken, err := signedToken.SignedString(s.privateKey)
	if err != nil {
		s.logger.Errorf("unable to sign jwt token: %s", err)
		s.sendOIDCError(w, http.StatusInternalServerError, "server_errror", "server_error")
		return
	}

	t := &Tokens{
		TokenType:   "Bearer",
		IDToken:     idToken,
		AccessToken: token.AccessToken,
		ExpiresIn:   int(time.Until(time.Unix(token.Exp, 0)).Seconds()),
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
	} else if token, err := s.tokens.GetTokenByAccessToken(accessToken); err != nil {
		if errors.Is(err, ErrNotFound) {
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
		user := s.getUser(token.UserID)
		data, _ = json.Marshal(user.Claims)
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
	s.tokens.Purge()
	w.Header().Add("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

func (s *Server) getClient(id string) *Client {
	for _, client := range s.clients {
		if client.ID == id {
			return client
		}
	}
	return nil
}

func (s *Server) getUser(username string) *User {
	for _, user := range s.users {
		if user.ID == username {
			return user
		}
	}
	return nil
}

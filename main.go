package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/bluele/gcache"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/gorilla/sessions"
	"github.com/oklog/ulid/v2"
	"github.com/ory/graceful"
	"github.com/spf13/cobra"
	"github.com/ugent-library/zaphttp"
	"github.com/ugent-library/zaphttp/zapchi"
	"go.uber.org/zap"
)

var logger *zap.SugaredLogger
var sessionStore *sessions.CookieStore
var endpoints *providerEndpoints

const sessionName = "MOCK_OIDC_SERVER_SESSION"
const clientID = "MOCK_OIDC_CLIENT_ID"

//const clientSecret = "MOCK_OIDC_CLIENT_SECRET"

var sessionSecret = []byte("ABCDEFGHIJKLMNOP")

var codes = gcache.New(100).LRU().Expiration(time.Hour).Build()

func initLogger() {
	l, e := zap.NewDevelopment()
	cobra.CheckErr(e)
	logger = l.Sugar()
}

func initSessionStore() {
	sessionStore = sessions.NewCookieStore(sessionSecret)
	sessionStore.MaxAge(3600)
	sessionStore.Options.Path = "/auth"
	sessionStore.Options.HttpOnly = true
	sessionStore.Options.Secure = false
}

func initEndpoints(uriBase string) {
	endpoints = &providerEndpoints{
		Issuer:                uriBase,
		AuthorizationEndpoint: uriBase + "/auth",
		TokenEndpoint:         uriBase + "/token",
		JWKSURI:               uriBase + "/certs",
		UserInfoEndpoint:      uriBase + "/userinfo",
		TokenEndpointAuthMethodsSupported: []string{
			"client_secret_basic",
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
		ClaimTypesSupported: []string{"normal"},
	}
}

func AuthGet(w http.ResponseWriter, r *http.Request) {
	session, _ := sessionStore.Get(r, sessionName)

	responseType := r.URL.Query().Get("response_type")
	state := r.URL.Query().Get("state")
	redirectURI := r.URL.Query().Get("redirect_uri")
	scope := r.URL.Query().Get("scope")

	redirectTo, err := url.ParseRequestURI(redirectURI)
	if err != nil {
		http.Error(w, "unable to parse parameter redirect_uri", http.StatusBadRequest)
		return
	}

	if responseType != "code" {
		http.Error(w, "response_type should equal 'code'", http.StatusBadRequest)
		return
	}
	if r.URL.Query().Get("client_id") != clientID {
		http.Error(w, "unexpected client id", http.StatusBadRequest)
		return
	}
	requestedScopes := strings.Split(scope, " ")
	for i := 0; i < len(requestedScopes); i++ {
		requestedScopes[i] = strings.TrimSpace(requestedScopes[i])
	}
	for _, rs := range requestedScopes {
		if !slices.Contains(endpoints.ScopesSupported, rs) {
			http.Error(w, "invalid scope "+rs, http.StatusBadRequest)
			return
		}
	}

	if oldCode, ok := session.Values["code"]; ok {
		q := redirectTo.Query()
		if state != "" {
			q.Add("state", state)
		}
		q.Add("code", oldCode.(string))
		redirectTo.RawQuery = q.Encode()
		http.Redirect(w, r, redirectTo.String(), http.StatusTemporaryRedirect)
		return
	}

	templateAuth.Execute(w, templateAuthParams{
		Scope:        scope,
		RedirectURI:  redirectURI,
		State:        state,
		ClientID:     clientID,
		ResponseType: responseType,
	})
}

func AuthPost(w http.ResponseWriter, r *http.Request) {
	session, _ := sessionStore.Get(r, sessionName)
	r.ParseForm()

	username := r.PostForm.Get("username")
	responseType := r.PostForm.Get("response_type")
	state := r.PostForm.Get("state")
	redirectURI := r.PostForm.Get("redirect_uri")
	scope := r.PostForm.Get("scope")

	redirectTo, err := url.ParseRequestURI(redirectURI)
	if err != nil {
		http.Error(w, "unable to parse parameter redirect_uri", http.StatusBadRequest)
		return
	}

	if responseType != "code" {
		http.Error(w, "response_type should equal 'code'", http.StatusBadRequest)
		return
	}
	if r.URL.Query().Get("client_id") != clientID {
		http.Error(w, "unexpected client id", http.StatusBadRequest)
		return
	}
	requestedScopes := strings.Split(scope, " ")
	for i := 0; i < len(requestedScopes); i++ {
		requestedScopes[i] = strings.TrimSpace(requestedScopes[i])
	}
	for _, rs := range requestedScopes {
		if !slices.Contains(endpoints.ScopesSupported, rs) {
			http.Error(w, "invalid scope "+rs, http.StatusBadRequest)
			return
		}
	}

	var authError string

	if username != "" {
		var user *User
		for _, u := range users {
			if u.Username == username {
				user = u
				break
			}
		}
		if user == nil {
			authError = "Unable to find user " + username
		} else {
			code := ulid.Make().String()
			session.Values["code"] = code
			if err := sessionStore.Save(r, w, session); err != nil {
				logger.Errorf("unable to save session: %s", err)
				http.Error(w, "unexpected error", http.StatusInternalServerError)
				return
			}
			if err := codes.Set(code, user); err != nil {
				logger.Errorf("unable to store mapping code to user: %s", err)
				http.Error(w, "unexpected error", http.StatusInternalServerError)
				return
			}
			q := redirectTo.Query()
			if state != "" {
				q.Add("state", state)
			}
			q.Add("code", code)
			redirectTo.RawQuery = q.Encode()
			http.Redirect(w, r, redirectTo.String(), http.StatusTemporaryRedirect)
			return
		}
	}

	templateAuth.Execute(w, templateAuthParams{
		Error:        authError,
		Scope:        scope,
		RedirectURI:  redirectURI,
		State:        state,
		ClientID:     clientID,
		ResponseType: responseType,
	})
}

func Discovery(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(200)
	w.Header().Add("Content-Type", "application/json")
	data, _ := json.Marshal(endpoints)
	w.Write(data)
}

func main() {
	initLogger()
	initSessionStore()
	initEndpoints("http://localhost:3000")

	mux := chi.NewMux()
	mux.Use(middleware.RequestID)
	mux.Use(middleware.RealIP)
	mux.Use(zaphttp.SetLogger(logger.Desugar(), zapchi.RequestID))
	mux.Use(middleware.RequestLogger(zapchi.LogFormatter()))
	mux.Use(middleware.Recoverer)

	mux.Get("/.well-known/openid-configuration", Discovery)
	mux.Get("/auth", AuthGet)
	mux.Post("/auth", AuthPost)

	srv := graceful.WithDefaults(&http.Server{
		Addr:         ":3000",
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	})
	if err := graceful.Graceful(srv.ListenAndServe, srv.Shutdown); err != nil {
		panic(err)
	}
	logger.Info("gracefully stopped server")
}

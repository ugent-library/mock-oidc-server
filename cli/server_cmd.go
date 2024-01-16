package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/oklog/ulid/v2"
	"github.com/ory/graceful"
	"github.com/spf13/cobra"
	"github.com/ugent-library/mock-oidc-server/mockoidc"
	"github.com/ugent-library/zaphttp"
	"github.com/ugent-library/zaphttp/zapchi"

	_ "github.com/joho/godotenv/autoload"
)

func loadClients() ([]*mockoidc.Client, error) {
	var clients []*mockoidc.Client
	reader, err := os.Open(config.ClientsPath)
	if err != nil {
		return nil, fmt.Errorf("unable to open clients file '%s': %w", config.ClientsPath, err)
	}
	dec := json.NewDecoder(reader)
	for {
		err := dec.Decode(&clients)
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("unable to parse clients: %w", err)
		}
	}
	return clients, nil
}

func loadUsers() ([]*mockoidc.User, error) {
	var users []*mockoidc.User
	reader, err := os.Open(config.UsersPath)
	if err != nil {
		return nil, fmt.Errorf("unable to open users file '%s': %w", config.UsersPath, err)
	}
	dec := json.NewDecoder(reader)
	for {
		err := dec.Decode(&users)
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, fmt.Errorf("unable to parse users: %w", err)
		}
	}
	return users, nil
}

func init() {
	rootCmd.AddCommand(serverCmd)
}

var serverCmd = &cobra.Command{
	Use:   "server",
	Short: "start server",
	RunE: func(cmd *cobra.Command, args []string) error {
		clients, err := loadClients()
		if err != nil {
			return err
		}

		users, err := loadUsers()
		if err != nil {
			return err
		}

		publicKey, err := loadRSAPublicKeyFromFile(config.PublicKeyPath)
		if err != nil {
			return err
		}

		privateKey, err := loadRSAPrivateKeyFromFile(config.PrivateKeyPath)
		if err != nil {
			return err
		}

		// TODO: as long as logins are stored in memory, cookies SHOULD be cleared on each restart
		// so only preload session secret when logins are stored remotely and store expiration time
		srvConfig := mockoidc.Config{
			SessionCookieName: config.SessionCookieName,
			SessionSecret:     ulid.Make().String(),
			URIBase:           config.URIBase,
			ExpiresIn:         time.Hour,
			PublicKey:         publicKey,
			PrivateKey:        privateKey,
			Logger:            logger,
			Users:             users,
			Clients:           clients,
			Store:             store,
		}

		oidcServer, err := mockoidc.NewServer(srvConfig)
		if err != nil {
			return err
		}

		mux := chi.NewMux()
		mux.Use(middleware.RequestID)
		mux.Use(middleware.RealIP)
		mux.Use(zaphttp.SetLogger(logger.Desugar(), zapchi.RequestID))
		mux.Use(middleware.RequestLogger(zapchi.LogFormatter()))
		mux.Use(middleware.Recoverer)

		mux.Get("/.well-known/openid-configuration", oidcServer.Discovery)
		mux.Get("/auth", oidcServer.AuthGet)
		mux.Post("/auth", oidcServer.AuthPost)
		mux.Post("/token", oidcServer.Token)
		mux.Get("/certs", oidcServer.Certs)
		mux.Get("/userinfo", oidcServer.UserInfo)
		mux.Get("/clear", oidcServer.Clear)

		addr := fmt.Sprintf("%s:%s", config.Host, config.Port)
		srv := graceful.WithDefaults(&http.Server{
			Addr:         addr,
			Handler:      mux,
			ReadTimeout:  10 * time.Second,
			WriteTimeout: 10 * time.Second,
		})

		logger.Infof("starting server at %s", addr)
		if err := graceful.Graceful(srv.ListenAndServe, srv.Shutdown); err != nil {
			return err
		}
		logger.Info("gracefully stopped server")
		return nil
	},
}

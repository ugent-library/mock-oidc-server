package cli

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
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
	var reader io.Reader
	var clients []*mockoidc.Client
	if config.Clients != "" {
		reader = strings.NewReader(config.Clients)
	} else if config.ClientsPath != "" {
		r, err := os.Open(config.ClientsPath)
		if err != nil {
			return nil, err
		}
		reader = r
	}
	dec := json.NewDecoder(reader)
	for {
		err := dec.Decode(&clients)
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, err
		}
	}
	return clients, nil
}

func loadUsers() ([]*mockoidc.User, error) {
	var reader io.Reader
	var users []*mockoidc.User
	if config.Users != "" {
		reader = strings.NewReader(config.Users)
	} else if config.UsersPath != "" {
		r, err := os.Open(config.UsersPath)
		if err != nil {
			return nil, err
		}
		reader = r
	}
	dec := json.NewDecoder(reader)
	for {
		err := dec.Decode(&users)
		if errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return nil, err
		}
	}
	return users, nil
}

func loadPublicKey() (*rsa.PublicKey, error) {
	if config.PublicKeyPath != "" {
		return loadRSAPublicKeyFromFile(config.PublicKeyPath)
	} else if config.PublicKey != "" {
		return parseRSAPublicKey([]byte(config.PublicKey))
	}
	return nil, errors.New("neither PUBLIC_KEY_PATH nor PUBLIC_KEY given")
}

func loadPrivateKey() (*rsa.PrivateKey, error) {
	if config.PrivateKeyPath != "" {
		return loadRSAPrivateKeyFromFile(config.PrivateKeyPath)
	} else if config.PrivateKey != "" {
		return parseRSAPrivateKey([]byte(config.PrivateKey))
	}
	return nil, errors.New("neither PRIVATE_KEY_PATH nor PRIVATE_KEY given")
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

		publicKey, err := loadPublicKey()
		if err != nil {
			return err
		}

		privateKey, err := loadPrivateKey()
		if err != nil {
			return err
		}

		// TODO: as long as logins are stored in memory, cookies SHOULD be cleared on each restart
		// so only preload session secret when logins are stored remotely
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

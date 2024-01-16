package cli

import (
	"crypto/rsa"
	"fmt"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

func loadRSAPublicKeyFromFile(file string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("unable to open public key '%s': %w", file, err)
	}
	return jwt.ParseRSAPublicKeyFromPEM(data)
}

func loadRSAPrivateKeyFromFile(file string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("unable to open private key '%s': %w", file, err)
	}
	return jwt.ParseRSAPrivateKeyFromPEM(data)
}

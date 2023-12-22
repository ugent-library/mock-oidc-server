package cli

import (
	"crypto/rsa"
	"os"

	"github.com/golang-jwt/jwt/v5"
)

func loadRSAPublicKeyFromFile(file string) (*rsa.PublicKey, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}

	return parseRSAPublicKey(data)
}

func parseRSAPublicKey(data []byte) (*rsa.PublicKey, error) {
	key, err := jwt.ParseRSAPublicKeyFromPEM(data)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func loadRSAPrivateKeyFromFile(file string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	return parseRSAPrivateKey(data)
}

func parseRSAPrivateKey(data []byte) (*rsa.PrivateKey, error) {
	key, err := jwt.ParseRSAPrivateKeyFromPEM(data)
	if err != nil {
		return nil, err
	}
	return key, nil
}

package main

import "github.com/ugent-library/mock-oidc-server/oidc"

var clients = []*oidc.Client{
	{
		ID:     "test",
		Secret: "test",
	},
}

package main

import "github.com/ugent-library/mock-oidc-server/oidc"

var users = []*oidc.User{
	{
		Username: "test",
		Claims: []*oidc.Claim{
			{
				Name:  "name",
				Value: "test user",
			},
			{
				Name:  "given_name",
				Value: "test",
			},
			{
				Name:  "family_name",
				Value: "user",
			},
			{
				Name:  "preferred_username",
				Value: "test",
			},
			{
				Name:  "email",
				Value: "test@user.be",
			},
		},
	},
}

package main

func GetUser(username string) *User {
	for _, user := range users {
		if user.Username == username {
			return user
		}
	}
	return nil
}

var users = []*User{
	{
		Username: "test",
		Claims: []*Claim{
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

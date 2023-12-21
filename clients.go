package main

var clients = []*Client{
	{
		ID:     "test",
		Secret: "test",
	},
}

func GetClient(id string) *Client {
	for _, client := range clients {
		if client.ID == id {
			return client
		}
	}
	return nil
}

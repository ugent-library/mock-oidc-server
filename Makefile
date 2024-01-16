build:
	go build

keys:
	mkdir -p data
	openssl genrsa -out data/oidc.rsa
	openssl rsa -in data/oidc.rsa -pubout > data/oidc.rsa.pub

test_keys:
	mkdir -p data
	cp data/oidc.rsa.example data/oidc.rsa
	cp data/oidc.rsa.pub.example data/oidc.rsa.pub

clean:
	rm -f data/*.rsa
	rm -f data/*.rsa.pub
	rm -f data/*.json
	rm mock-oidc-server

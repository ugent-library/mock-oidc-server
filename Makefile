build:
	go build

keys:
	mkdir -p .data
	openssl genrsa -out .data/oidc.rsa
	openssl rsa -in .data/oidc.rsa -pubout > .data/oidc.rsa.pub

clean:
	rm -rf .data
	rm /mock-oidc-server

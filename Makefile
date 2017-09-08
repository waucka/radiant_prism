all: radiant_prism_server radiant_prism_client helpers

helpers:
	$(MAKE) -C helpers all

radiant_prism_server: server/main.go httpserver/httpserver.go auth/auth.go
	go build -o radiant_prism_server github.com/waucka/radiant_prism/server

radiant_prism_client: client/main.go
	go build -o radiant_prism_client github.com/waucka/radiant_prism/client

clean:
	rm -f *~ radiant_prism_server radiant_prism_client
	$(MAKE) -C helpers clean

.PHONY: all clean helpers

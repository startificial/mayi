// The BFF listens behind an application's same-origin HTTPS reverse proxy.
package main

import (
	"encoding/base64"
	cryptoadapter "github.com/startificial/mayi/examples/bff/adapters/crypto"
	"github.com/startificial/mayi/examples/bff/app"
	"io"
	"log"
	"net/http"
	"os"
	"time"
)

func main() {
	key, err := base64.RawURLEncoding.DecodeString(os.Getenv("BFF_ENCRYPTION_KEY"))
	if err != nil || len(key) != 32 {
		log.Fatal("invalid BFF configuration")
	}
	handler, err := app.New(app.Config{Tenant: os.Getenv("BFF_TENANT"), Issuer: os.Getenv("BFF_ISSUER"), Resource: os.Getenv("BFF_RESOURCE"), Client: os.Getenv("BFF_CLIENT_ID"), Secret: os.Getenv("BFF_CLIENT_SECRET"), Origin: os.Getenv("BFF_ORIGIN"), ObjectType: os.Getenv("BFF_OBJECT_TYPE"), Keys: []cryptoadapter.Key{{ID: "v1", Bytes: key, Active: true}}})
	clear(key)
	if err != nil {
		log.Fatal("invalid BFF configuration")
	}
	server := &http.Server{Addr: "127.0.0.1:8081", Handler: handler, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 15 * time.Second, IdleTimeout: 30 * time.Second, MaxHeaderBytes: 16 << 10, ErrorLog: log.New(io.Discard, "", 0)}
	if err = server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatal("BFF server stopped")
	}
}

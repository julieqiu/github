package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"

	log "github.com/julieqiu/dlog"
	"github.com/julieqiu/github/internal/client"
	"github.com/julieqiu/github/internal/worker"
)

const (
	owner    = "golang"
	repoName = "vulndb"
)

var tok = flag.String("tok", "", "GitHub access token")

func main() {
	ctx := context.Background()
	flag.Parse()
	if *tok == "" {
		log.Fatalf(ctx, "no token")
	}
	if err := run(ctx, repoName, *tok); err != nil {
		log.Fatal(ctx, err)
	}
}

func run(ctx context.Context, repoName, tok string) error {
	client := client.New(owner, repoName, tok)
	if _, err := worker.NewServer(ctx, client); err != nil {
		return err
	}
	addr := ":6060"
	log.Infof(ctx, "Listening on addr http://localhost%s", addr)
	return fmt.Errorf("listening: %v", http.ListenAndServe(addr, nil))
}

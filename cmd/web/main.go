package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"

	log "github.com/julieqiu/dlog"
	"github.com/julieqiu/github/internal/client"
	"github.com/julieqiu/github/internal/colly"
	"github.com/julieqiu/github/internal/worker"
	vulnc "golang.org/x/vuln/client"
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
	githubClient := client.New(ctx, owner, repoName, tok)
	dbs := []string{"https://vuln.go.dev"}
	dbClient, err := vulnc.NewClient(dbs, vulnc.Options{})
	if err != nil {
		return err
	}
	collyClient := colly.New()
	if _, err := worker.NewServer(ctx, githubClient, dbClient, collyClient); err != nil {
		return err
	}
	addr := ":6060"
	log.Infof(ctx, "Listening on addr http://localhost%s", addr)
	return fmt.Errorf("listening: %v", http.ListenAndServe(addr, nil))
}

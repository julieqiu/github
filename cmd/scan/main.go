package main

import (
	"context"
	"flag"
	"log"

	"github.com/julieqiu/github/internal/client"
	"github.com/julieqiu/github/internal/stats"
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
		log.Fatalf("no token")
	}
	if err := run(ctx, repoName, *tok); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, repo, tok string) error {
	client := client.New(owner, repoName, tok)
	return stats.Stats(ctx, client)
}

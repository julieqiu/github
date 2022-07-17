package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	"github.com/julieqiu/github/internal/client"
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
	issues, err := client.ListByRepo(ctx)
	if err != nil {
		return err
	}
	for _, i := range issues {
		fmt.Printf("(%s) #%d: %s | %v\n", i.State, i.Number, i.Title, i.Labels)
	}
	return nil
}

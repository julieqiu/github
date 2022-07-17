package stats

import (
	"context"

	"github.com/julieqiu/github/internal/client"
	"github.com/julieqiu/github/internal/colly"
)

func Stats(ctx context.Context, githubClient *client.Client, collyClient *colly.Client) error {
	collyClient.ReleaseNotes()
	return nil
}

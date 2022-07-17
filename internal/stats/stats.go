package stats

import (
	"context"
	"fmt"

	"github.com/julieqiu/github/internal/client"
)

func Stats(ctx context.Context, client *client.Client) error {
	issues, err := client.ListByRepo(ctx)
	if err != nil {
		return err
	}
	for _, i := range issues {
		if i.IsStdLib() || i.Open() {
			continue
		}
		if i.Labels["NotGoVuln"] || i.Labels["NeedsReport"] || i.Labels["duplicate"] {
			continue
		}
		if i.CVE != "" {
			fmt.Printf("(%s) #%d: %s %s | %v\n", i.State, i.Number, i.CVE, i.ModulePath, i.Labels)
		}
	}
	for _, i := range issues {
		if i.IsStdLib() || i.Open() || !i.IsVuln() {
			continue
		}
		if i.Labels["NotGoVuln"] || i.Labels["NeedsReport"] || i.Labels["duplicate"] {
			continue
		}
		if i.GHSA != "" {
			fmt.Printf("(%s) #%d: %s %s | %v\n", i.State, i.Number, i.GHSA, i.ModulePath, i.Labels)
		}
	}
	return nil
}

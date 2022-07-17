// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package client provides a GitHub client for interacting with issues.
package client

import (
	"context"
	"time"

	"github.com/google/go-github/v41/github"
	"github.com/julieqiu/derrors"
	"golang.org/x/oauth2"
)

// An Issue represents a GitHub issue or similar.
type Issue struct {
	Number    int
	Title     string
	Body      string
	Labels    []string
	CreatedAt time.Time
	State     string
}

type Client struct {
	client *github.Client
	owner  string
	repo   string
}

// New creates a Client that will create issues in
// the a GitHub repo.
// A GitHub access token is required to create issues.
func New(owner, repo, accessToken string) *Client {
	ts := oauth2.StaticTokenSource(&oauth2.Token{AccessToken: accessToken})
	tc := oauth2.NewClient(context.Background(), ts)
	return &Client{
		client: github.NewClient(tc),
		owner:  owner,
		repo:   repo,
	}
}

// ListByRepo lists the issues for the repository.
//
// GitHub API docs: https://docs.github.com/en/free-pro-team@latest/rest/reference/issues/#list-repository-issues
func (c *Client) ListByRepo(ctx context.Context) (_ []*Issue, err error) {
	defer derrors.Wrap(&err, "ListByRepo(ctx)")
	opts := &github.IssueListByRepoOptions{
		ListOptions: github.ListOptions{PerPage: 100},
	}
	opts.State = "open"
	open, _, err := c.client.Issues.ListByRepo(ctx, c.owner, c.repo, opts)
	if err != nil {
		return nil, err
	}
	opts.State = "closed"
	closed, _, err := c.client.Issues.ListByRepo(ctx, c.owner, c.repo, opts)
	if err != nil {
		return nil, err
	}

	var out []*Issue
	for _, i := range append(open, closed...) {
		if i.PullRequestLinks != nil {
			continue
		}
		out = append(out, &Issue{
			Number: *i.Number,
			Title:  *i.Title,
			Labels: func() []string {
				var labels []string
				for _, l := range i.Labels {
					labels = append(labels, *l.Name)
				}
				return labels
			}(),
			CreatedAt: *i.CreatedAt,
			Body:      *i.Body,
			State:     *i.State,
		})
	}
	return out, nil
}

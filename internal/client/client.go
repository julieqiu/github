// Copyright 2022 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package client provides a GitHub client for interacting with issues.
package client

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/google/go-github/v41/github"
	"github.com/julieqiu/derrors"
	"golang.org/x/oauth2"
)

const (
	LabelNeedsCVEID     = "NeedsCVEID"
	LabelNeedsCVERecord = "NeedsCVERecord"
	LabelNeedsReport    = "NeedsReport"
	LabelNotGoVuln      = "NotGoVuln"
	LabelStdLib         = "stdlib"
	LabelDuplicate      = "duplicate"
)

// An Issue represents a GitHub issue or similar.
type Issue struct {
	Number     int
	Title      string
	Body       string
	Labels     map[string]bool
	CreatedAt  time.Time
	State      string
	ModulePath string
	CVE        string
	GHSA       string
}

func (i *Issue) IsStdLib() bool {
	if i.Labels[LabelStdLib] {
		return true
	}
	return strings.Contains(i.Title, "potential Go vuln in std")
}
func (i *Issue) Open() bool {
	return i.State == "open"
}

func (i *Issue) Closed() bool {
	return i.State == "closed"
}

func (i *Issue) IsVuln() bool {
	if i.Labels[LabelNotGoVuln] {
		return false
	}
	if i.Labels[LabelNeedsReport] {
		return true
	}
	return true
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
	opts := &github.IssueListByRepoOptions{}

	opts.State = "open"
	open, err := c.listByRepo(ctx, opts)
	if err != nil {
		return nil, err
	}

	opts.State = "closed"
	closed, err := c.listByRepo(ctx, opts)
	if err != nil {
		return nil, err
	}

	var out []*Issue
	for _, i := range append(open, closed...) {
		if i.PullRequestLinks != nil {
			continue
		}
		i2, err := constructIssue(i)
		if err != nil {
			return nil, err
		}
		out = append(out, i2)
	}
	return out, nil
}

func (c *Client) listByRepo(ctx context.Context, opts *github.IssueListByRepoOptions) (_ []*github.Issue, err error) {
	opts.ListOptions = github.ListOptions{Page: 1, PerPage: 100}
	var out []*github.Issue
	for {
		issues, _, err := c.client.Issues.ListByRepo(ctx, c.owner, c.repo, opts)
		if err != nil {
			return nil, err
		}
		if len(issues) == 0 {
			break
		}
		opts.Page += 1
		out = append(out, issues...)
	}
	return out, nil
}

func constructIssue(issue *github.Issue) (*Issue, error) {
	i2 := &Issue{
		Number:    *issue.Number,
		Title:     *issue.Title,
		CreatedAt: *issue.CreatedAt,
		Body:      *issue.Body,
		State:     *issue.State,
		Labels:    map[string]bool{},
	}
	for _, l := range issue.Labels {
		i2.Labels[*l.Name] = true
	}
	// Dummy issues were created for these issues.
	if i2.Number <= 139 {
		return i2, nil
	}

	mp, cve, err := parseModulePathAndCVE(*issue.Title)
	if err != nil {
		return nil, err
	}
	i2.ModulePath = mp
	if strings.Contains(cve, "CVE") {
		i2.CVE = cve
	} else {
		i2.GHSA = cve
	}
	return i2, nil
}

var titleRegexp = regexp.MustCompile(`^x\/vulndb: potential Go vuln in (.+): (.*)$`)

func parseModulePathAndCVE(title string) (string, string, error) {
	m := titleRegexp.FindStringSubmatch(title)
	if len(m) != 3 {
		fmt.Println(m)
		return "", "", fmt.Errorf("%q: not a valid title", title)
	}
	return m[1], m[2], nil
}

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
	"golang.org/x/vuln/osv"
)

// An Issue represents a GitHub issue or similar.
type Issue struct {
	Number      int
	Title       string
	Body        string
	Labels      map[string]bool
	CreatedAt   time.Time
	ModulePath  string
	PackagePath string
	Introduced  []string
	Fixed       []string
	CVE         string
	GHSA        string
	IsStdLib    bool
	Open        bool
	HasReport   bool
	OSV         *osv.Entry
}

func (i *Issue) LabeledNotGoVuln() bool {
	return i.Labels["NotGoVuln"]
}

func (i *Issue) LabeledNeedsReport() bool {
	return i.Labels["NeedsReport"]
}

func (i *Issue) LabeledDuplicate() bool {
	return i.Labels["duplicate"]
}

func (i *Issue) LabeledStdLib() bool {
	return i.Labels["stdlib"]
}

func (i *Issue) LabeledNeedsCVEID() bool {
	return i.Labels["NeedsCVEID"]
}

func (i *Issue) LabeledNeedsCVERecord() bool {
	return i.Labels["NeedsCVERecord"]
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
	fmt.Printf("%d open issues, including PRs\n", len(open))
	fmt.Printf("%d closed issues, including PRs\n", len(closed))

	for k, v := range closed {
		open[k] = v
	}
	fmt.Printf("%d total issues, including PRs\n", len(open))

	var (
		out   []*Issue
		dummy int
		prs   int
	)
	for _, issue := range open {
		if issue.IsPullRequest() {
			prs += 1
			continue
		}
		if *issue.Number <= 139 {
			dummy += 1
			if *issue.State == "open" {
				fmt.Println("open: ", *issue.Number)
			}
			continue
		}
		i2, err := constructIssue(issue)
		if err != nil {
			return nil, err
		}
		out = append(out, i2)
	}
	fmt.Printf("%d dummy issues (skipped)\n", dummy)
	fmt.Printf("%d PRs (skipped) \n", prs)
	return out, nil
}

func (c *Client) listByRepo(ctx context.Context, opts *github.IssueListByRepoOptions) (_ map[int]*github.Issue, err error) {
	opts.ListOptions = github.ListOptions{Page: 1, PerPage: 100}
	out := map[int]*github.Issue{}
	for {
		issues, _, err := c.client.Issues.ListByRepo(ctx, c.owner, c.repo, opts)
		if err != nil {
			return nil, err
		}
		if len(issues) == 0 {
			break
		}
		opts.Page += 1
		for _, iss := range issues {
			out[*iss.Number] = iss
		}
	}
	return out, nil
}

func constructIssue(issue *github.Issue) (*Issue, error) {
	i2 := &Issue{
		Number:    *issue.Number,
		Title:     *issue.Title,
		CreatedAt: *issue.CreatedAt,
		Body:      *issue.Body,
		Labels:    map[string]bool{},
	}
	isl, err := isStdLib(issue)
	if err != nil {
		return nil, err
	}
	i2.IsStdLib = isl
	for _, l := range issue.Labels {
		i2.Labels[*l.Name] = true
	}
	if *issue.State == "open" {
		i2.Open = true
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

func isStdLib(issue *github.Issue) (bool, error) {
	for _, label := range issue.Labels {
		if *label.Name == "stdlib" {
			return true, nil
		}
	}
	mp, _, err := parseModulePathAndCVE(*issue.Title)
	if err != nil {
		return false, err
	}
	return !strings.Contains(mp, "."), nil
}

var titleRegexp = regexp.MustCompile(`^x\/vulndb: potential Go vuln in (.+): (.*)$`)

func parseModulePathAndCVE(title string) (string, string, error) {
	m := titleRegexp.FindStringSubmatch(title)
	if len(m) != 3 {
		fmt.Println(m)
		return "", "", fmt.Errorf("%q: not a valid title", title)
	}
	mp := strings.TrimSuffix(strings.TrimPrefix(m[1], `"`), `"`)
	return mp, m[2], nil
}

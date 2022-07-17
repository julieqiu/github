// Copyright 2021 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package worker

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/safehtml/template"
	"github.com/julieqiu/derrors"
	log "github.com/julieqiu/dlog"
	"github.com/julieqiu/github/internal/client"
	"github.com/julieqiu/github/internal/colly"
	"golang.org/x/sync/errgroup"
	vulnc "golang.org/x/vuln/client"
	"golang.org/x/vuln/osv"
)

const pkgsiteURL = "https://pkg.go.dev"

var staticPath = template.TrustedSourceFromConstant("static")

type Server struct {
	indexTemplate *template.Template
	gitHubClient  *client.Client
	dbClient      vulnc.Client
	collyClient   *colly.Client
}

func NewServer(ctx context.Context, githubClient *client.Client, vulndbClient vulnc.Client, collyClient *colly.Client) (_ *Server, err error) {
	defer derrors.Wrap(&err, "NewServer")

	s := &Server{
		gitHubClient: githubClient,
		dbClient:     vulndbClient,
		collyClient:  collyClient,
	}
	s.indexTemplate, err = parseTemplate(staticPath, template.TrustedSourceFromConstant("index.tmpl"))
	if err != nil {
		return nil, err
	}
	s.handle(ctx, "/", s.indexPage)
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir(staticPath.String()))))
	s.handle(ctx, "/favicon.ico", func(w http.ResponseWriter, r *http.Request) error {
		http.ServeFile(w, r, filepath.Join(staticPath.String(), "favicon.ico"))
		return nil
	})
	return s, nil
}

func (s *Server) handle(_ context.Context, pattern string, handler func(w http.ResponseWriter, r *http.Request) error) {
	http.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		ctx := r.Context()
		w2 := &responseWriter{ResponseWriter: w}
		if err := handler(w2, r); err != nil {
			s.serveError(ctx, w2, r, err)
		}
	})
}

type serverError struct {
	status int   // HTTP status code
	err    error // wrapped error
}

func (s *serverError) Error() string {
	return fmt.Sprintf("%d (%s): %v", s.status, http.StatusText(s.status), s.err)
}

func (s *Server) serveError(ctx context.Context, w http.ResponseWriter, _ *http.Request, err error) {
	serr, ok := err.(*serverError)
	if !ok {
		serr = &serverError{status: http.StatusInternalServerError, err: err}
	}
	if serr.status == http.StatusInternalServerError {
		log.Errorf(ctx, serr.err.Error())
	} else {
		log.Warningf(ctx, "returning %d (%s) for error %v", serr.status, http.StatusText(serr.status), err)
	}
	http.Error(w, serr.err.Error(), serr.status)
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

func translateStatus(code int) int64 {
	if code == 0 {
		return http.StatusOK
	}
	return int64(code)
}

// Parse a template.
func parseTemplate(staticPath, filename template.TrustedSource) (*template.Template, error) {
	if staticPath.String() == "" {
		return nil, nil
	}
	templatePath := template.TrustedSourceJoin(staticPath, filename)
	return template.New(filename.String()).Funcs(template.FuncMap{
		"timefmt": FormatTime,
	}).ParseFilesFromTrustedSources(templatePath)
}

var locNewYork *time.Location

func init() {
	var err error
	locNewYork, err = time.LoadLocation("America/New_York")
	if err != nil {
		log.Errorf(context.Background(), "time.LoadLocation: %v", err)
		os.Exit(1)
	}
}

func FormatTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.In(locNewYork).Format("2006-01-02 15:04:05")
}

func renderPage(ctx context.Context, w http.ResponseWriter, page interface{}, tmpl *template.Template) (err error) {
	defer derrors.Wrap(&err, "renderPage")

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, page); err != nil {
		return err
	}
	if _, err := io.Copy(w, &buf); err != nil {
		log.Errorf(ctx, "copying buffer to ResponseWriter: %v", err)
		return err
	}
	return nil
}

type StdLibReport struct {
	client.Issue
	ReleaseNote *colly.ReleaseNote
}

type indexPage struct {
	NumIssues         int
	NumOpen           int
	NumClosed         int
	NumDBReports      int
	StdLibIssues      []*StdLibReport
	OpenIssues        []*client.Issue
	ClosedNotGoVuln   []*client.Issue
	ClosedNeedsReport []*client.Issue
	ClosedDuplicate   []*client.Issue
	ClosedOther       []*client.Issue
	DBReports         map[int]*osv.Entry
	ReleaseNotes      []*colly.ReleaseNote
}

func (s *Server) indexPage(w http.ResponseWriter, r *http.Request) error {
	g, ctx := errgroup.WithContext(r.Context())
	dbReports := map[int]string{}
	g.Go(func() error {
		ids, err := s.dbClient.ListIDs(ctx)
		if err != nil {
			return err
		}
		fmt.Println("ListIDs: ", len(ids))
		for _, id := range ids {
			parts := strings.Split(id, "-")
			n, err := strconv.Atoi(parts[2])
			if err != nil {
				return err
			}
			dbReports[n] = id
		}
		fmt.Println("dbReports: ", len(dbReports))
		return nil
	})
	var issues []*client.Issue
	g.Go(func() error {
		issues2, err := s.gitHubClient.ListByRepo(r.Context())
		if err != nil {
			return err
		}
		fmt.Println(len(issues2))
		issues = issues2
		return nil
	})
	var releaseNotes []*colly.ReleaseNote
	g.Go(func() error {
		releaseNotes = s.collyClient.ReleaseNotes()
		return nil
	})
	if err := g.Wait(); err != nil {
		return err
	}

	g, ctx = errgroup.WithContext(r.Context())
	for _, i := range issues {
		i := i
		g.Go(func() error {
			if goid, ok := dbReports[i.Number]; ok {
				i.HasReport = true
				osv, err := s.dbClient.GetByID(ctx, goid)
				if err != nil {
					return err
				}
				i.OSV = osv
				for _, aff := range osv.Affected {
					i.PackagePath = aff.Package.Name
					for _, r := range aff.Ranges {
						for _, event := range r.Events {
							if event.Introduced != "" {
								i.Introduced = append(i.Introduced, event.Introduced)
							}
							if event.Fixed != "" {
								i.Fixed = append(i.Fixed, event.Fixed)
							}
						}
					}
				}
			}
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return err
	}

	page := &indexPage{
		NumDBReports: len(dbReports),
		DBReports:    map[int]*osv.Entry{},
		ReleaseNotes: releaseNotes,
	}
	fmt.Println(page.NumDBReports)
	for _, i := range issues {
		page.DBReports[i.Number] = i.OSV

		page.NumIssues += 1
		if i.Open {
			page.NumOpen += 1
		} else {
			page.NumClosed += 1
		}
		if i.IsStdLib {
			report := &StdLibReport{
				Issue: *i,
			}
			page.StdLibIssues = append(page.StdLibIssues, report)
			continue
		}
		if i.Open {
			page.OpenIssues = append(page.OpenIssues, i)
		} else {
			if i.Labels["NotGoVuln"] {
				page.ClosedNotGoVuln = append(page.ClosedNotGoVuln, i)
			} else if i.Labels["NeedsReport"] {
				page.ClosedNeedsReport = append(page.ClosedNeedsReport, i)
			} else if i.Labels["duplicate"] {
				page.ClosedDuplicate = append(page.ClosedDuplicate, i)
			} else {
				page.ClosedOther = append(page.ClosedDuplicate, i)
			}
		}
	}

	sort.Slice(page.StdLibIssues, func(i, j int) bool {
		return page.StdLibIssues[i].PackagePath < page.StdLibIssues[j].PackagePath
	})
	sort.Slice(page.OpenIssues, func(i, j int) bool {
		return page.OpenIssues[i].ModulePath < page.OpenIssues[j].ModulePath
	})
	sort.Slice(page.ClosedNeedsReport, func(i, j int) bool {
		return page.ClosedNeedsReport[i].ModulePath < page.ClosedNeedsReport[j].ModulePath
	})
	// sort.Slice(page.ClosedIssues, func(i, j int) bool {
	// return page.ClosedIssues[i].ModulePath < page.ClosedIssues[j].ModulePath
	// })
	return renderPage(r.Context(), w, page, s.indexTemplate)
}

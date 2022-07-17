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
	"time"

	"github.com/google/safehtml/template"
	"github.com/julieqiu/derrors"
	log "github.com/julieqiu/dlog"
	"github.com/julieqiu/github/internal/client"
	"golang.org/x/sync/errgroup"
)

const pkgsiteURL = "https://pkg.go.dev"

var staticPath = template.TrustedSourceFromConstant("static")

type Server struct {
	indexTemplate *template.Template
	gitHubClient  *client.Client
}

func NewServer(ctx context.Context, client *client.Client) (_ *Server, err error) {
	defer derrors.Wrap(&err, "NewServer")

	s := &Server{gitHubClient: client}
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

type indexPage struct {
	NumClosed         int
	StdLibIssues      []*client.Issue
	OpenIssues        []*client.Issue
	ClosedNotGoVuln   []*client.Issue
	ClosedNeedsReport []*client.Issue
	ClosedDuplicate   []*client.Issue
	ClosedOther       []*client.Issue
}

func (s *Server) indexPage(w http.ResponseWriter, r *http.Request) error {
	g, _ := errgroup.WithContext(r.Context())
	g.Go(func() error {
		return nil
	})
	if err := g.Wait(); err != nil {
		return err
	}

	issues, err := s.gitHubClient.ListByRepo(r.Context())
	if err != nil {
		return err
	}
	page := &indexPage{}
	for _, i := range issues {
		if i.IsStdLib {
			page.StdLibIssues = append(page.StdLibIssues, i)
			continue
		}
		if i.Open {
			page.OpenIssues = append(page.OpenIssues, i)
		} else {
			page.NumClosed += 1
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

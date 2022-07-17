package colly

import (
	"strings"
	"time"

	"github.com/gocolly/colly/v2"
)

type Client struct {
	colly *colly.Collector
}

func New() *Client {
	// Instantiate default collector
	c := colly.NewCollector()
	c.SetRequestTimeout(60 * time.Second)
	return &Client{colly: c}
}

type ReleaseNote struct {
	Version     string
	Description string
}

const releaseNotesURL = "https://go.dev/doc/devel/release"

func (c *Client) ReleaseNotes() []*ReleaseNote {
	var notes []*ReleaseNote
	c.colly.OnHTML("p", func(e *colly.HTMLElement) {
		id := e.Attr("id")
		if id == "" {
			return
		}

		n := &ReleaseNote{
			Version: id,
		}
		if strings.Contains(e.Text, "security") {
			n.Description = strings.Join(strings.Fields(e.Text), " ")
		}
		notes = append(notes, n)
	})
	c.colly.Visit(releaseNotesURL)
	return notes
}

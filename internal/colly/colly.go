package colly

import (
	"strings"
	"time"

	"github.com/gocolly/colly/v2"
)

type Client struct {
	url   string
	colly *colly.Collector
}

func New(url string) *Client {
	// Instantiate default collector
	c := colly.NewCollector()
	c.SetRequestTimeout(60 * time.Second)
	return &Client{colly: c, url: url}
}

type ReleaseNote struct {
	Version     string
	Description string
}

func (c *Client) ReleaseNotes() string {
	var notes []string
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
			return
		}
	})
	c.colly.Visit(c.url)
	return
}

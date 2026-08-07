package intel

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"
)

type Feed struct {
	Name       string
	URL        string
	Path       string
	Category   string
	Confidence int
	TTL        time.Duration
}

func DefaultFeeds(customPath string) []Feed {
	return []Feed{
		{
			Name:       "feodotracker",
			URL:        "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
			Category:   "botnet-c2",
			Confidence: 90,
			TTL:        7 * 24 * time.Hour,
		},
		{
			Name:       "blocklist.de",
			URL:        "https://lists.blocklist.de/lists/all.txt",
			Category:   "attacker",
			Confidence: 60,
			TTL:        48 * time.Hour,
		},
		{
			Name:       "custom",
			Path:       customPath,
			Category:   "internal",
			Confidence: 95,
			TTL:        365 * 24 * time.Hour,
		},
	}
}

func Fetch(ctx context.Context, f Feed, client *http.Client) ([]Indicator, error) {
	var lines []string
	var err error

	if f.Path != "" {
		lines, err = readFile(f.Path)
	} else {
		lines, err = readURL(ctx, f.URL, client)
	}
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	out := []Indicator{}
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		fields := strings.Fields(line)
		value := fields[0]

		category := f.Category
		confidence := f.Confidence
		if len(fields) >= 2 {
			category = fields[1]
		}
		if len(fields) >= 3 {
			if n, err := strconv.Atoi(fields[2]); err == nil {
				confidence = n
			}
		}

		kind := ""
		if _, err := netip.ParseAddr(value); err == nil {
			kind = KindIP
		} else if _, err := netip.ParsePrefix(value); err == nil {
			kind = KindCIDR
		} else {
			continue
		}

		out = append(out, Indicator{
			Indicator:  value,
			Kind:       kind,
			Source:     f.Name,
			Category:   category,
			Confidence: confidence,
			LastSeen:   now,
			ExpiresAt:  now.Add(f.TTL),
		})
	}
	return out, nil
}

func readURL(ctx context.Context, url string, client *http.Client) ([]string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "SentinelX/1.0 (educational security platform)")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("fetch %s returned %s", url, resp.Status)
	}
	return scan(resp.Body)
}
func readFile(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return scan(f)
}

func scan(r io.Reader) ([]string, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	lines := []string{}
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	return lines, sc.Err()
}

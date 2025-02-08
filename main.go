package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"bakscan/common"
)

// Иногда в ответе бывают редиректы, состоящие из одного тега meta либо script
var htmlRegexp = regexp.MustCompile(`<(?i:html|body|script|meta)[^<>]*>`)

type Config struct {
	InputFile      string
	OutputDir      string
	Threads        int
	ConnectTimeout time.Duration
	Timeout        time.Duration
	SkipVerify     bool
	ProxyURL       string
}

func parseFlags() *Config {
	c := &Config{}
	flag.StringVar(&c.InputFile, "i", "-", "Input file")
	flag.StringVar(&c.OutputDir, "o", "./output", "Output directory to found files")
	flag.IntVar(&c.Threads, "t", 200, "Number of threads")
	flag.DurationVar(&c.Timeout, "с", 10*time.Second, "Connect timeout")
	flag.DurationVar(&c.Timeout, "T", 60*time.Second, "Timeout for entire request")
	flag.BoolVar(&c.SkipVerify, "k", false, "Skip SSL verification")
	flag.StringVar(&c.ProxyURL, "p", "", "Proxy URL")
	flag.Parse()
	return c
}

func main() {
	conf := parseFlags()

	l := log.New(os.Stderr, "", 0)

	urls, err := common.ReadLines(conf.InputFile)
	if err != nil {
		l.Fatal(err)
	}

	client, err := common.CreateHTTPClient(conf.ConnectTimeout, conf.SkipVerify, conf.ProxyURL)
	if err != nil {
		l.Fatalf("\033[31mFailed to create HTTP client: %v\033[0m", err)
	}

	wg := &sync.WaitGroup{}
	sem := make(chan struct{}, conf.Threads)
	mu := &sync.Mutex{}
	var counter int64

	banner := []string{
		"______       _    _____                 ",
		"| ___ \\     | |  /  ___|                ",
		"| |_/ / __ _| | _\\ `--.  ___ __ _ _ __  ",
		"| ___ \\/ _` | |/ /`--. \\/ __/ _` | '_ \\ ",
		"| |_/ | (_| |   </\\__/ | (_| (_| | | | |",
		"\\____/ \\__,_|_|\\_\\____/ \\___\\__,_|_| |_|",
	}

	l.Println("\033[36m" + strings.Join(banner, "\n") + "\033[0m")

	l.Println("\033[33mStarting scanning...\033[0m")

	for _, urlStr := range urls {
		u, err := url.Parse(urlStr)
		if err != nil {
			l.Printf("\033[31mError parsing URL %q: %v\033[0m", urlStr, err)
			continue
		}

		for _, file := range generateSensitiveFiles(u.Hostname()) {
			fileURL, err := common.JoinURL(u, "/"+strings.TrimLeft(file, "/"))
			if err != nil {
				l.Printf("\033[31mError joining URL: %v\033[0m\n", err)
				continue
			}

			wg.Add(1)
			sem <- struct{}{}
			go func(fileURL string) {
				defer func() {
					wg.Done()
					<-sem
				}()

				userAgent := common.GenerateRandomUserAgent()
				l.Printf("\033[34m%s: %s\033[0m\n", fileURL, userAgent)

				ctx, cancel := context.WithTimeout(context.Background(), conf.Timeout)
				defer cancel()

				resp, err := common.Fetch(ctx, client, fileURL, userAgent)
				if err != nil {
					l.Printf("\033[31mFetch error: %v\033[0m\n", err)
					return
				}
				defer resp.Body.Close()

				if resp.StatusCode != http.StatusOK {
					l.Printf("\033[31m%d - %s\033[0m\n", resp.StatusCode, fileURL)
					return
				}

				buf := make([]byte, 4096)
				readBytes, err := resp.Body.Read(buf)
				if err != nil && err != io.EOF {
					l.Printf("\033[31mReading error: %v\033[0m\n", err)
					return
				}

				if readBytes == 0 {
					l.Printf("\033[31mSkip empty: %s\033[0m\n", fileURL)
					return
				}

				content := buf[:readBytes]
				if htmlRegexp.MatchString(string(content)) {
					l.Printf("\033[31mSkip HTML: %s\033[0m\n", fileURL)
					return
				}

				// l.Printf("\033[32mFound: %s\033[0m\n", fileURL)
				// log.Logger потокобезопасен в отличии от Print*
				mu.Lock()
				fmt.Println(fileURL)
				mu.Unlock()

				outputPath := filepath.Join(conf.OutputDir, resp.Request.URL.Host)
				if err := os.MkdirAll(outputPath, 0o755); err != nil && !os.IsExist(err) {
					l.Printf("\033[31mError creating directory: %v\033[0m\n", err)
					return
				}

				decodedPath, err := url.PathUnescape(resp.Request.URL.Path)
				if err != nil {
					l.Printf("\033[31mError decoding path: %v\033[0m\n", err)
					return
				}

				filePath := common.SanitizePath(filepath.Join(outputPath, decodedPath))
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

				l.Printf("\033[32mSaved: %s\033[0m\n", filePath)
				atomic.AddInt64(&counter, 1)
			}(fileURL)
		}
	}

	wg.Wait()
	close(sem)
	l.Println("\033[33mScanning finished!\033[0m")
	l.Printf("\033[35mTotal saved: %d\033[0m\n", counter)
}

// https://support.plesk.com/hc/en-us/articles/12377082525719-Site-traffic-suddenly-increased
func generateSensitiveFiles(domainName string) []string {
	commonFiles := []string{
		".aws/credentials",
		".bash_history",
		".bashrc",
		".config/gcloud/credentials.db",
		".config/gcloud/credentials.json",
		".config/openvpn/auth.txt",
		".DS_Store",
		".env.dev",
		".env.prod",
		".env.test",
		".env",
		".git-credentials",
		".git/config",
		".gitconfig",
		".gitignore",
		".idea/dataSources.local.xml",
		".idea/dataSources.xml",
		".idea/workspace.xml",
		".netrc",
		".pgpass",
		".python_history",
		".ssh/authorized_keys",
		".ssh/id_rsa",
		".ssh/known_hosts",
		".vscode/sftp.json",
		".zsh_history",
		".zshrc",
		"docker-compose.yaml",
		"docker-compose.yml",
		"Dockerfile.dev",
		"Dockerfile.prod",
		"Dockerfile.test",
		"Dockerfile",
	}

	phpConfigs := []string{
		"app/etc/env.php",
		"bitrix/php_interface/dbconn.php",
		"config.local.php",
		"config.php",
		"config/settings.inc.php",
		"configuration.php",
		"database.php",
		"settings.php",
		"sites/default/settings.php",
		"wp-config.php",
	}

	backupSuffixes := []string{".bak", ".1", ".old", ".swp", "~"}

	archiveNames := []string{
		"archive",
		"backup",
		"files",
		"home",
		"httpdocs",
		"public_html",
		"root",
		"site",
		"web",
		"www",
		"wwwroot",
		domainName,
	}
	archiveExtensions := []string{".rar", ".tar.gz", ".tar.xz", ".tgz", ".zip"}

	sqlDumpNames := []string{
		"backup",
		"database",
		"db_dump",
		"db_export",
		"db",
		"dump",
		domainName,
	}

	sqlDumpExtensions := []string{".sql"}

	logPrefixes := []string{"", "logs/"}
	logNames := []string{"error", "debug"}
	logSuffixes := []string{".log", "_log"}

	return common.Extend(
		commonFiles,
		common.GenerateCombinations(phpConfigs, backupSuffixes),
		common.GenerateCombinations(archiveNames, archiveExtensions),
		common.GenerateCombinations(sqlDumpNames, sqlDumpExtensions),
		common.GenerateCombinations(logPrefixes, logNames, logSuffixes),
	)
}

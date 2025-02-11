package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"bakscan/common"
	"bakscan/console"
)

var (
	htmlRegexp         = regexp.MustCompile(`<(?i:\!doctype|html)[^>]*>`)
	invalidStatusError = errors.New("invalid status code")
	fileIsHTMLError    = errors.New("file contains HTML")
	tooSmallError      = errors.New("file too small")
)

type Config struct {
	InputFile         string
	OutputDir         string
	Threads           int
	ConnectTimeout    time.Duration
	ReadHeaderTimeout time.Duration
	TotalTimeout      time.Duration
	Delay             time.Duration
	SkipVerify        bool
	UserAgent         string
	ProxyURL          string
}

func parseFlags() *Config {
	c := &Config{}
	flag.StringVar(&c.InputFile, "i", "-", "Input file")
	flag.StringVar(&c.OutputDir, "o", "./output", "Output directory to found files")
	flag.IntVar(&c.Threads, "t", runtime.NumCPU()*10, "Number of threads")
	flag.DurationVar(&c.ConnectTimeout, "сt", 10*time.Second, "Connect timeout")
	flag.DurationVar(&c.ReadHeaderTimeout, "rht", 5*time.Second, "Read header timeout")
	flag.DurationVar(&c.TotalTimeout, "tt", 60*time.Second, "Timeout for entire request")
	flag.DurationVar(&c.Delay, "d", 20*time.Millisecond, "Delay beetween requests")
	flag.BoolVar(&c.SkipVerify, "k", false, "Skip SSL verification")
	flag.StringVar(&c.UserAgent, "ua", "", "Custom User-Agent, e.g. \"Mozilla/5.0 (compatible; YandexBot/3.0; +http://yandex.com/bots) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0\"")
	flag.StringVar(&c.ProxyURL, "p", "", "Proxy URL")
	flag.Parse()
	return c
}

func main() {
	conf := parseFlags()
	urls, err := common.ReadLines(conf.InputFile)
	if err != nil {
		console.Fatal("Error read URLs: %v", err)
	}
	if len(urls) == 0 {
		console.Fatal("Nothing to scan.")
	}
	client, err := common.CreateHTTPClient(conf.ConnectTimeout, conf.ReadHeaderTimeout, conf.SkipVerify, conf.ProxyURL)
	if err != nil {
		console.Fatal("Failed to create HTTP client: %v", err)
	}
	wg := &sync.WaitGroup{}
	sem := make(chan struct{}, conf.Threads)
	mu := &sync.Mutex{}
	rateLimiter := time.NewTicker(conf.Delay)
	defer rateLimiter.Stop()
	var counter int64
	console.Info("______       _    _____                 ")
	console.Info("| ___ \\     | |  /  ___|                ")
	console.Info("| |_/ / __ _| | _\\ `--.  ___ __ _ _ __  ")
	console.Info("| ___ \\/ _` | |/ /`--. \\/ __/ _` | '_ \\ ")
	console.Info("| |_/ | (_| |   </\\__/ | (_| (_| | | | |")
	console.Info("\\____/ \\__,_|_|\\_\\____/ \\___\\__,_|_| |_|")
	console.Info("Starting scanning...")
	for _, urlStr := range urls {
		u, err := url.Parse(urlStr)
		if err != nil {
			console.Error("Error parsing URL %q: %v", urlStr, err)
			continue
		}
		sensitiveFiles := generateSensitiveFiles(u.Hostname())
		common.Shuffle(sensitiveFiles)
		console.Info("Checking %d sensitive files on the site %s", len(sensitiveFiles), u)
		for _, file := range sensitiveFiles {
			fileURL, err := common.JoinURL(u, "/"+strings.TrimLeft(file, "/"))
			if err != nil {
				console.Error("Error joining URL: %v", err)
				continue
			}
			wg.Add(1)
			sem <- struct{}{}
			// Nginx и прочие сервера как правило учитывают лишь время начала запроса при ограничении их количества в период времени
			// Должен быть вне горутины или
			<-rateLimiter.C // Ожидаем следующего запроса
			go func(fileURL, userAgent string) {
				defer func() {
					wg.Done()
					<-sem
				}()
				ctx, cancel := context.WithTimeout(context.Background(), conf.TotalTimeout)
				defer cancel()
				if userAgent == "" {
					userAgent = common.GenerateRandomUserAgent()
				}
				console.Log("Try to download %s with User-Agent: %s", fileURL, userAgent)
				filePath, err := download(ctx, client, fileURL, userAgent, conf.OutputDir)
				if err != nil {
					switch {
					case errors.Is(err, invalidStatusError):
						console.Warn("Skipping file (invalid status): %s => %v", fileURL, err)
					case errors.Is(err, fileIsHTMLError):
						console.Warn("Skipping file (contains HTML): %s => %v", fileURL, err)
					case errors.Is(err, tooSmallError):
						console.Warn("Skipping file (too small): %s => %v", fileURL, err)
					default:
						console.Warn("Download error: %s => %v", fileURL, err)
					}
					return
				}
				mu.Lock()
				fmt.Println(fileURL)
				mu.Unlock()
				console.Success("Saved: %s", filePath)
				atomic.AddInt64(&counter, 1)
			}(fileURL, conf.UserAgent)
		}
	}
	wg.Wait()
	close(sem)
	console.Info("Scanning finished!")
	if counter > 0 {
		console.Success("Saved files: %d", counter)
	} else {
		console.Error("Nothing found ;-(")
	}
}

func download(ctx context.Context, client *http.Client, fileURL, userAgent, outputDir string) (string, error) {
	resp, err := common.Fetch(ctx, client, fileURL, userAgent)
	if err != nil {
		return "", fmt.Errorf("fetch error: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", invalidStatusError
	}

	// const maxFileSize = 10 * 1024 * 1024
	// contentLength, err := strconv.Atoi(resp.Header.Get("Content-Length"))
	// if err == nil && contentLength > maxFileSize {
	// 	return "", fileTooLargeError
	// }

	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return "", fmt.Errorf("error directory: %w", err)
	}

	tmpFile, err := os.CreateTemp(outputDir, "download-*.tmp")
	if err != nil {
		return "", fmt.Errorf("error creating temp file: %w", err)
	}
	defer os.Remove(tmpFile.Name())

	_, err = io.Copy(tmpFile, resp.Body)
	if err != nil {
		return "", fmt.Errorf("error saving response body: %w", err)
	}

	fileInfo, err := tmpFile.Stat()
	if err != nil {
		return "", fmt.Errorf("error getting file Info: %w", err)
	}
	if fileInfo.Size() <= 100 {
		return "", tooSmallError
	}

	_, err = tmpFile.Seek(0, io.SeekStart)
	if err != nil {
		return "", fmt.Errorf("error seeking file: %w", err)
	}

	buf := make([]byte, 4096)
	n, err := tmpFile.Read(buf)
	if err != nil {
		return "", fmt.Errorf("error reading file: %w", err)
	}

	if htmlRegexp.Match(buf[:n]) {
		return "", fileIsHTMLError
	}

	outputPath := filepath.Join(outputDir, resp.Request.URL.Hostname())
	decodedPath, err := url.PathUnescape(resp.Request.URL.Path)
	if err != nil {
		return "", fmt.Errorf("error decoding path: %w", err)
	}

	finalFilePath := common.SanitizePath(filepath.Join(outputPath, decodedPath))

	// Воссоздаем файловую структуру пути до файла на сервере
	dir := filepath.Dir(finalFilePath)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("error creating directories: %w", err)
	}

	if err := os.Rename(tmpFile.Name(), finalFilePath); err != nil {
		return "", fmt.Errorf("error moving file: %w", err)
	}

	return finalFilePath, nil
}

func generateSensitiveFiles(domainName string) []string {
	siteBackups := common.GenerateCombinations(
		[]string{
			"archive",
			"backup",
			"docroot",
			"files",
			"home",
			"html",
			"httpdocs",
			"old",
			"public_html",
			"root",
			"site",
			"web",
			"www",
			domainName,
		},
		[]string{".tar.gz", ".tgz", ".tar.xz", ".tar.bz2", ".zip", ".rar"},
	)
	sqlBackups := common.GenerateCombinations(
		[]string{
			"backup",
			"database",
			"db_dump",
			"db_export",
			"db",
			"dump",
			domainName,
		},
		[]string{".sql"},
	)
	mongoBackups := common.GenerateCombinations(
		[]string{"backup", "dump"},
		[]string{"/admin/system.users.bson"},
	)
	phpConfigBackups := common.GenerateCombinations(
		[]string{
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
		},
		[]string{".bak", ".bk", ".old", ".swp", "~"},
	)
	dockerPrefixes := []string{"", "docker/"}
	stageSuffixes := []string{"", ".prod", ".dev"}
	dockerFiles := common.GenerateCombinations(dockerPrefixes, []string{"Dockerfile", ".env"}, stageSuffixes)
	dockerComposeFiles := common.GenerateCombinations(
		dockerPrefixes,
		[]string{"docker-compose"},
		stageSuffixes,
		[]string{".yml", ".yaml"},
	)
	otherDeployFiles := []string{
		".circleci/config.yml",
		".drone.yml",
		".github/workflows/deploy.yml",
		".gitlab-ci.yml",
		".travis.yml",
		"bitbucket-pipelines.yml",
		"deploy.sh",
		"Jenkinsfile",
	}
	logFiles := common.GenerateCombinations(
		[]string{"", "logs/"},
		[]string{"error", "debug"},
		[]string{".log", "_log"},
	)
	homeFiles := []string{
		".aws/credentials",
		".bash_history",
		".bashrc",
		".config/gcloud/credentials.db",
		".config/gcloud/credentials.json",
		".config/openvpn/auth.txt",
		".DS_Store",
		".git-credentials",
		".git/config",
		".gitconfig",
		".idea/dataSources.local.xml",
		".idea/dataSources.xml",
		".idea/workspace.xml",
		".netrc",
		".pgpass",
		".python_history",
		".ssh/authorized_keys",
		".ssh/id_ed25519",
		".ssh/id_rsa",
		".ssh/known_hosts",
		".vscode/sftp.json",
		".zsh_history",
		".zshrc",
		".kube/config",
	}
	miscFiles := []string{
		"config.json",
		"config.xml",
		"config.yaml",
		"config.yml",
		"includes/database/database.inc", // конфиг drupal до D7, который может быть доступен из-за неправильной настройки сервера
		"passwords.csv",
		"user_secrets.yml", // Конфиг от open stack хранится в /etc обычно, но чем черт не шутит
		"users.csv",
		".gitignore", // может содержать путь до бекапов
	}
	return common.Extend(
		siteBackups,
		sqlBackups,
		mongoBackups,
		phpConfigBackups,
		dockerFiles,
		dockerComposeFiles,
		otherDeployFiles,
		logFiles,
		homeFiles,
		miscFiles,
	)
}

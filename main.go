package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
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
)

const (
	// Константы для цветов
	CSI       = "\033["
	Reset     = CSI + "0m" // Сброс всех стилей
	Bold      = CSI + "1m" // Жирный текст
	Dim       = CSI + "2m" // Тусклый текст
	Italic    = CSI + "3m" // Курсив
	Underline = CSI + "4m" // Подчеркивание
	Blink     = CSI + "5m" // Мигающий текст
	Reverse   = CSI + "7m" // Инверсия цветов
	Hidden    = CSI + "8m" // Скрытый текст

	// Основные цвета текста
	Black   = CSI + "30m"
	Red     = CSI + "31m"
	Green   = CSI + "32m"
	Yellow  = CSI + "33m"
	Blue    = CSI + "34m"
	Magenta = CSI + "35m"
	Cyan    = CSI + "36m"
	White   = CSI + "37m"

	// Яркие цвета текста
	BrightBlack   = CSI + "90m" // Серый
	BrightRed     = CSI + "91m"
	BrightGreen   = CSI + "92m"
	BrightYellow  = CSI + "93m"
	BrightBlue    = CSI + "94m"
	BrightMagenta = CSI + "95m"
	BrightCyan    = CSI + "96m"
	BrightWhite   = CSI + "97m"

	// Цвета фона
	BgBlack   = CSI + "40m"
	BgRed     = CSI + "41m"
	BgGreen   = CSI + "42m"
	BgYellow  = CSI + "43m"
	BgBlue    = CSI + "44m"
	BgMagenta = CSI + "45m"
	BgCyan    = CSI + "46m"
	BgWhite   = CSI + "47m"

	// Яркие цвета фона
	BgBrightBlack   = CSI + "100m" // Темно-серый фон
	BgBrightRed     = CSI + "101m"
	BgBrightGreen   = CSI + "102m"
	BgBrightYellow  = CSI + "103m"
	BgBrightBlue    = CSI + "104m"
	BgBrightMagenta = CSI + "105m"
	BgBrightCyan    = CSI + "106m"
	BgBrightWhite   = CSI + "107m"
)

var (
	EOL = common.GetEOL()
	// Иногда в ответе бывают редиректы, состоящие из одного тега meta либо script
	htmlRegexp         = regexp.MustCompile(`<(?i:html|body|script|meta)[^<>]*>`)
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
	if len(urls) == 0 {
		l.Fatalln(BrightRed+"Nothing to scan."+Reset, err)
	}
	client, err := common.CreateHTTPClient(conf.ConnectTimeout, conf.ReadHeaderTimeout, conf.SkipVerify, conf.ProxyURL)
	if err != nil {
		l.Fatalf(BrightRed+"Failed to create HTTP client: %v"+Reset, err)
	}
	wg := &sync.WaitGroup{}
	sem := make(chan struct{}, conf.Threads)
	mu := &sync.Mutex{}
	rateLimiter := time.NewTicker(conf.Delay)
	defer rateLimiter.Stop()
	var counter int64
	l.Println(BrightBlue + "______       _    _____                 " + Reset)
	l.Println(BrightBlue + "| ___ \\     | |  /  ___|                " + Reset)
	l.Println(BrightBlue + "| |_/ / __ _| | _\\ `--.  ___ __ _ _ __  " + Reset)
	l.Println(BrightBlue + "| ___ \\/ _` | |/ /`--. \\/ __/ _` | '_ \\ " + Reset)
	l.Println(BrightBlue + "| |_/ | (_| |   </\\__/ | (_| (_| | | | |" + Reset)
	l.Println(BrightBlue + "\\____/ \\__,_|_|\\_\\____/ \\___\\__,_|_| |_|" + Reset)
	l.Println("")
	l.Println(BrightBlue + "Starting scanning..." + Reset)
	l.Println("")
	for _, urlStr := range urls {
		u, err := url.Parse(urlStr)
		if err != nil {
			l.Printf(BrightRed+"Error parsing URL %q: %v"+Reset, urlStr, err)
			continue
		}
		sensitiveFiles := generateSensitiveFiles(u.Hostname())
		common.Shuffle(sensitiveFiles)
		l.Printf(BrightBlue+"Checking %d sensitive files on the site %s"+Reset+EOL, len(sensitiveFiles), u)
		for _, file := range sensitiveFiles {
			fileURL, err := common.JoinURL(u, "/"+strings.TrimLeft(file, "/"))
			if err != nil {
				l.Printf(BrightRed+"Error joining URL: %v"+Reset+EOL, err)
				continue
			}
			wg.Add(1)
			sem <- struct{}{}
			// Nginx и прочие сервера как правило учитывают лишь время начала запроса при ограничении их количества в период времени
			// Должен быть вне горутины или
			<-rateLimiter.C // Ожидаем следующего запроса
			go func(fileURL string) {
				defer func() {
					wg.Done()
					<-sem
				}()
				ctx, cancel := context.WithTimeout(context.Background(), conf.TotalTimeout)
				defer cancel()
				l.Printf(BrightWhite+"[%s] Try to download file: %s"+Reset+EOL, time.Now().Format("2006-01-02 15:04:05.000000"), fileURL)
				filePath, err := download(ctx, client, fileURL, conf.OutputDir)
				if err != nil {
					switch {
					case errors.Is(err, invalidStatusError):
						l.Printf(BrightYellow+"Skipping file (invalid status): %s => %v"+Reset+EOL, fileURL, err)
					case errors.Is(err, fileIsHTMLError):
						l.Printf(BrightYellow+"Skipping file (contains HTML): %s => %v"+Reset+EOL, fileURL, err)
					case errors.Is(err, tooSmallError):
						l.Printf(BrightYellow+"Skipping file (too small): %s => %v"+Reset+EOL, fileURL, err)
					default:
						l.Printf(BrightRed+"Download error: %s => %v"+Reset+EOL, fileURL, err)
					}
					return
				}
				mu.Lock()
				fmt.Println(fileURL)
				mu.Unlock()
				l.Printf(BrightGreen+"Saved: %s"+Reset+EOL, filePath)
				atomic.AddInt64(&counter, 1)
			}(fileURL)
		}
	}
	wg.Wait()
	close(sem)
	l.Println("")
	l.Println(BrightBlue + "Scanning finished!" + Reset)
	l.Println("")
	if counter > 0 {
		l.Printf(BrightGreen+"Saved files: %d"+Reset+EOL, counter)
	} else {
		l.Println(BrightRed + "Nothing found ;-(" + Reset)
	}
}

func download(ctx context.Context, client *http.Client, fileURL, outputDir string) (string, error) {
	userAgent := common.GenerateRandomUserAgent()
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
		return "", fmt.Errorf("error getting file info: %w", err)
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
	if err := os.MkdirAll(outputPath, 0o755); err != nil {
		return "", fmt.Errorf("error directory: %w", err)
	}

	decodedPath, err := url.PathUnescape(resp.Request.URL.Path)
	if err != nil {
		return "", fmt.Errorf("error decoding path: %w", err)
	}

	finalFilePath := common.SanitizePath(filepath.Join(outputPath, decodedPath))
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
		[]string{".bak", ".1", ".old", ".swp", "~"},
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
	miscFiles := []string{
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
		"passwords.csv",
		"users.csv",
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
		miscFiles,
	)
}

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

// Константы для цветов
const (
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

	Gray = BrightBlack

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

// Иногда в ответе бывают редиректы, состоящие из одного тега meta либо script
var htmlRegexp = regexp.MustCompile(`<(?i:html|body|script|meta)[^<>]*>`)

type Config struct {
	InputFile         string
	OutputDir         string
	Threads           int
	ConnectTimeout    time.Duration
	ReadHeaderTimeout time.Duration
	TotalTimeout      time.Duration
	SkipVerify        bool
	ProxyURL          string
}

func parseFlags() *Config {
	c := &Config{}
	flag.StringVar(&c.InputFile, "i", "-", "Input file")
	flag.StringVar(&c.OutputDir, "o", "./output", "Output directory to found files")
	flag.IntVar(&c.Threads, "t", 200, "Number of threads")
	flag.DurationVar(&c.ConnectTimeout, "сt", 10*time.Second, "Connect timeout")
	flag.DurationVar(&c.ReadHeaderTimeout, "rht", 5*time.Second, "Read header timeout")
	flag.DurationVar(&c.TotalTimeout, "tt", 60*time.Second, "Timeout for entire request")
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
	client, err := common.CreateHTTPClient(conf.ConnectTimeout, conf.ReadHeaderTimeout, conf.SkipVerify, conf.ProxyURL)
	if err != nil {
		l.Fatalf(Red+"Failed to create HTTP client: %v"+Reset, err)
	}
	wg := &sync.WaitGroup{}
	sem := make(chan struct{}, conf.Threads)
	mu := &sync.Mutex{}
	// var fetchedCount int64
	var savedCount int64
	banner := []string{
		"______       _    _____                 ",
		"| ___ \\     | |  /  ___|                ",
		"| |_/ / __ _| | _\\ `--.  ___ __ _ _ __  ",
		"| ___ \\/ _` | |/ /`--. \\/ __/ _` | '_ \\ ",
		"| |_/ | (_| |   </\\__/ | (_| (_| | | | |",
		"\\____/ \\__,_|_|\\_\\____/ \\___\\__,_|_| |_|",
	}
	l.Println(Green + strings.Join(banner, "\n") + Reset)
	l.Println(Yellow + "Starting scanning..." + Reset)
	for _, urlStr := range urls {
		u, err := url.Parse(urlStr)
		if err != nil {
			l.Printf(Red+"Error parsing URL %q: %v"+Reset, urlStr, err)
			continue
		}
		for _, file := range generateSensitiveFiles(u.Hostname()) {
			fileURL, err := common.JoinURL(u, "/"+strings.TrimLeft(file, "/"))
			if err != nil {
				l.Printf(Red+"Error joining URL: %v"+Reset+"\n", err)
				continue
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(fileURL string) {
				defer func() {
					wg.Done()
					<-sem
				}()
				ctx, cancel := context.WithTimeout(context.Background(), conf.TotalTimeout)
				defer cancel()
				userAgent := common.GenerateRandomUserAgent()
				l.Printf(Gray+"%s => %s"+Reset+"\n", fileURL, userAgent)
				resp, err := common.Fetch(ctx, client, fileURL, userAgent)
				if err != nil {
					l.Printf(Red+"Fetch error: %v"+Reset+"\n", err)
					return
				}
				defer resp.Body.Close()
				// atomic.AddInt64(&fetchedCount, 1)
				if resp.StatusCode != http.StatusOK {
					l.Printf(Red+"%d - %s"+Reset+"\n", resp.StatusCode, fileURL)
					return
				}
				buf := make([]byte, 4096)
				readBytes, err := resp.Body.Read(buf)
				if err != nil && err != io.EOF {
					l.Printf(Red+"Reading error: %v"+Reset+"\n", err)
					return
				}
				if readBytes == 0 {
					l.Printf(Red+"Skip empty: %s"+Reset+"\n", fileURL)
					return
				}
				content := buf[:readBytes]
				if htmlRegexp.MatchString(string(content)) {
					l.Printf(Red+"Skip HTML: %s"+Reset+"\n", fileURL)
					return
				}
				mu.Lock()
				fmt.Println(fileURL)
				mu.Unlock()
				outputPath := filepath.Join(conf.OutputDir, resp.Request.URL.Host)
				if err := os.MkdirAll(outputPath, 0o755); err != nil && !os.IsExist(err) {
					l.Printf(Red+"Error creating directory: %v"+Reset+"\n", err)
					return
				}
				decodedPath, err := url.PathUnescape(resp.Request.URL.Path)
				if err != nil {
					l.Printf(Red+"Error decoding path: %v"+Reset+"\n", err)
					return
				}
				filePath := common.SanitizePath(filepath.Join(outputPath, decodedPath))
				file, err := os.Create(filePath)
				if err != nil {
					l.Printf(Red+"Error creating file: %v"+Reset+"\n", err)
					return
				}
				defer file.Close()
				if _, err := file.Write(content); err != nil {
					l.Printf(Red+"Error writing file: %v"+Reset+"\n", err)
					return
				}
				_, err = io.Copy(file, resp.Body)
				if err != nil {
					l.Printf(Red+"Error saving remaining response body: %v"+Reset+"\n", err)
				}
				l.Printf(Green+"Saved: %s"+Reset+"\n", filePath)
				atomic.AddInt64(&savedCount, 1)
			}(fileURL)
		}
	}
	wg.Wait()
	close(sem)
	l.Println(Yellow + "Scanning finished!" + Reset)
	// l.Printf(Blue+"Fetched URLs: %d"+Reset+"\n", fetchedCount)
	if savedCount > 0 {
		l.Printf(Green+"Saved files: %d"+Reset+"\n", savedCount)
	} else {
		l.Println(Red + "Nothing found ;-(" + Reset)
	}
}

func generateSensitiveFiles(domainName string) []string {
	baseFiles := []string{
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
		"docroot",
		"files",
		"home",
		"httpdocs",
		"public_html",
		"root",
		"site",
		"web",
		"www",
		domainName,
	}
	archiveExtensions := []string{".rar", ".tar.gz", ".tgz", ".zip"}
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
	envSuffixes := []string{"", ".prod", ".dev"}
	dockerPrefixes := []string{"", "docker/"}
	dockerFiles := []string{"Dockerfile", ".env"}
	composeFiles := []string{"docker-compose"}
	yamlExtensions := []string{".yml", ".yaml"}
	logPrefixes := []string{"", "logs/"}
	logNames := []string{"error", "debug"}
	logSuffixes := []string{".log", "_log"}
	return common.Extend(
		baseFiles,
		common.GenerateCombinations(phpConfigs, backupSuffixes),
		common.GenerateCombinations(archiveNames, archiveExtensions),
		common.GenerateCombinations(sqlDumpNames, sqlDumpExtensions),
		common.GenerateCombinations(dockerPrefixes, dockerFiles, envSuffixes),
		common.GenerateCombinations(dockerPrefixes, composeFiles, envSuffixes, yamlExtensions),
		common.GenerateCombinations(logPrefixes, logNames, logSuffixes),
	)
}

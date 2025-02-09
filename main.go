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

const (
	NL = "\n"

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
	flag.IntVar(&c.Threads, "t", 100, "Number of threads")
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
		l.Fatalf(BrightRed+"Failed to create HTTP client: %v"+Reset, err)
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
	l.Println(BrightGreen + strings.Join(banner, NL) + Reset)
	l.Println(BrightCyan + "Starting scanning..." + Reset)
	for _, urlStr := range urls {
		u, err := url.Parse(urlStr)
		if err != nil {
			l.Printf(BrightRed+"Error parsing URL %q: %v"+Reset, urlStr, err)
			continue
		}
		sensitiveFiles := generateSensitiveFiles(u.Hostname())
		l.Printf(BrightCyan+"Checking %d sensitive files on the site %s"+Reset+NL, len(sensitiveFiles), u)
		for _, file := range sensitiveFiles {
			fileURL, err := common.JoinURL(u, "/"+strings.TrimLeft(file, "/"))
			if err != nil {
				l.Printf(BrightRed+"Error joining URL: %v"+Reset+NL, err)
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
				l.Printf(BrightWhite+"%s => %s"+Reset+NL, fileURL, userAgent)
				resp, err := common.Fetch(ctx, client, fileURL, userAgent)
				if err != nil {
					l.Printf(BrightRed+"Fetch error: %v"+Reset+NL, err)
					return
				}
				defer resp.Body.Close()
				// atomic.AddInt64(&fetchedCount, 1)
				if resp.StatusCode != http.StatusOK {
					l.Printf(BrightRed+"%d - %s"+Reset+NL, resp.StatusCode, fileURL)
					return
				}
				buf := make([]byte, 4096)
				readBytes, err := resp.Body.Read(buf)
				if err != nil && err != io.EOF {
					l.Printf(BrightRed+"Reading error: %v"+Reset+NL, err)
					return
				}
				if readBytes == 0 {
					l.Printf(BrightRed+"Skip empty: %s"+Reset+NL, fileURL)
					return
				}
				content := buf[:readBytes]
				if htmlRegexp.MatchString(string(content)) {
					l.Printf(BrightRed+"Skip HTML: %s"+Reset+NL, fileURL)
					return
				}
				mu.Lock()
				fmt.Println(fileURL)
				mu.Unlock()
				outputPath := filepath.Join(conf.OutputDir, resp.Request.URL.Hostname())
				if err := os.MkdirAll(outputPath, 0o755); err != nil && !os.IsExist(err) {
					l.Printf(BrightRed+"Error creating directory: %v"+Reset+NL, err)
					return
				}
				decodedPath, err := url.PathUnescape(resp.Request.URL.Path)
				if err != nil {
					l.Printf(BrightRed+"Error decoding path: %v"+Reset+NL, err)
					return
				}
				filePath := common.SanitizePath(filepath.Join(outputPath, decodedPath))
				file, err := os.Create(filePath)
				if err != nil {
					l.Printf(BrightRed+"Error creating file: %v"+Reset+NL, err)
					return
				}
				defer file.Close()
				if _, err := file.Write(content); err != nil {
					l.Printf(BrightRed+"Error writing file: %v"+Reset+NL, err)
					return
				}
				_, err = io.Copy(file, resp.Body)
				if err != nil {
					l.Printf(BrightRed+"Error saving remaining response body: %v"+Reset+NL, err)
				}
				l.Printf(BrightGreen+"Saved: %s"+Reset+NL, filePath)
				atomic.AddInt64(&savedCount, 1)
			}(fileURL)
		}
	}
	wg.Wait()
	close(sem)
	l.Println(BrightGreen + "Scanning finished!" + Reset)
	// l.Printf(Blue+"Fetched URLs: %d"+Reset+NL, fetchedCount)
	if savedCount > 0 {
		l.Printf(BrightGreen+"Saved files: %d"+Reset+NL, savedCount)
	} else {
		l.Println(BrightRed + "Nothing found ;-(" + Reset)
	}
}

func generateSensitiveFiles(domainName string) []string {
	stageSuffixes := []string{"", ".prod", ".dev"}
	dockerPrefixes := []string{"", "docker/"}
	return common.Extend(
		// Общие файлы
		[]string{
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
			// В этих конфигах IDEA могут быть креды от баз
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
			// На всякий случай проверим
			"users.csv",
			"passwords.csv",
		},
		// Бекапы конфигов PHP
		common.GenerateCombinations([]string{
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
		}, []string{".bak", ".1", ".old", ".swp", "~"}),
		// Бекапы всего сайта
		common.GenerateCombinations([]string{
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
		}, []string{".rar", ".tar.gz", ".tgz", ".zip"}),
		// Бекапы SQL-баз
		common.GenerateCombinations([]string{
			"backup",
			"database",
			"db_dump",
			"db_export",
			"db",
			"dump",
			domainName,
		}, []string{".sql"}),
		// Бекапы MongoDB
		common.GenerateCombinations([]string{
			"backup",
			"dump",
		}, []string{"/admin/system.users.bson"}),
		// Файлы докера
		common.GenerateCombinations(dockerPrefixes, []string{"Dockerfile", ".env"}, stageSuffixes),
		common.GenerateCombinations(dockerPrefixes, []string{"docker-compose"}, stageSuffixes, []string{".yml", ".yaml"}),
		// Логи, содержащие ошибки или отладочную информацию
		common.GenerateCombinations([]string{"", "logs/"}, []string{"error", "debug"}, []string{".log", "_log"}),
	)
}

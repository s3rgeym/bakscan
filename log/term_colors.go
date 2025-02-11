package log

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

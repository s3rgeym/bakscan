package logger

import (
	"log"
	"os"
)

var l = log.New(os.Stderr, "", log.LstdFlags)

func PrintColor(color, format string, v ...interface{}) {
	l.Printf(color+format+Reset, v...)
}

func Success(format string, v ...interface{}) {
	PrintColor(BrightGreen, format, v...)
}

func Warn(format string, v ...interface{}) {
	PrintColor(BrightYellow, format, v...)
}

func Error(format string, v ...interface{}) {
	PrintColor(BrightRed, format, v...)
}

func Info(format string, v ...interface{}) {
	PrintColor(BrightBlue, format, v...)
}

func Log(format string, v ...interface{}) {
	PrintColor(BrightWhite, format, v...)
}

func Fatal(format string, v ...interface{}) {
	PrintColor(Bold+Red, format, v...)
	os.Exit(1)
}

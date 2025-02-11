package logger

import (
	"log"
	"os"
)

var l = log.New(os.Stderr, "", log.LstdFlags)

func Print(color, format string, v ...interface{}) {
	l.Printf(color+format+Reset, v...)
}

func Success(format string, v ...interface{}) {
	Print(BrightGreen, format, v...)
}

func Warn(format string, v ...interface{}) {
	Print(BrightYellow, format, v...)
}

func Error(format string, v ...interface{}) {
	Print(BrightRed, format, v...)
}

func Info(format string, v ...interface{}) {
	Print(BrightBlue, format, v...)
}

func Log(format string, v ...interface{}) {
	Print(BrightWhite, format, v...)
}

func Fatal(format string, v ...interface{}) {
	Print(Bold+Red, format, v...)
	os.Exit(1)
}

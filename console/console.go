package console

import (
	"log"
	"os"
)

var l = log.New(os.Stderr, "", log.LstdFlags)

func printColor(color, format string, v ...interface{}) {
	l.Printf(color+format+Reset, v...)
}

func Success(format string, v ...interface{}) {
	printColor(BrightGreen, format, v...)
}

func Warn(format string, v ...interface{}) {
	printColor(BrightYellow, format, v...)
}

func Error(format string, v ...interface{}) {
	printColor(BrightRed, format, v...)
}

func Info(format string, v ...interface{}) {
	printColor(BrightBlue, format, v...)
}

func Log(format string, v ...interface{}) {
	printColor(BrightWhite, format, v...)
}

func Fatal(format string, v ...interface{}) {
	printColor(Bold+Red, format, v...)
	os.Exit(1)
}

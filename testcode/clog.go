package main

import (
	"fmt"
	"github.com/fatih/color"
	"path"
	"runtime"
	"strings"
	"sync"
	"time"
)

var (
	clog_output_mutex = sync.Mutex{}
)

func clog_print(args ...interface{}) {
	clog_output_mutex.Lock()
	defer clog_output_mutex.Unlock()
	fmt.Print(args...)
}

func clog_println(args ...interface{}) {
	clog_output_mutex.Lock()
	defer clog_output_mutex.Unlock()
	fmt.Print("\r  \r")
	fmt.Println(args...)
}

func clog_printf(format string, args ...interface{}) {
	clog_output_mutex.Lock()
	defer clog_output_mutex.Unlock()
	fmt.Print("\r  \r")
	fmt.Printf(format, args...)
}

func custom_log(level string, format string, args ...interface{}) {
	clog_output_mutex.Lock()
	defer clog_output_mutex.Unlock()

	var func_name string = ""
	var file string = ""
	var line int = 0

	var pc uintptr
	var ok bool
	func_name = "?"
	pc, file, line, ok = runtime.Caller(1)
	if ok {
		func_obj := runtime.FuncForPC(pc)
		if func_obj != nil {
			func_name = func_obj.Name()
		}
	} else {
		file = "?"
		line = 0
	}
	file = path.Base(file)
	file = file + ":"
	func_name = "(" + func_name + ")"

	// colored output
	var level_color *color.Color
	switch strings.ToLower(level) {
	case "trace":
		level_color = color.New(color.Reset, color.Faint, color.FgHiWhite, color.BgHiBlack)
	case "debug":
		level_color = color.New(color.Reset, color.FgBlack, color.BgYellow)
	case "info":
		level_color = color.New(color.Reset, color.FgBlack, color.BgHiWhite)
	case "warn":
		level_color = color.New(color.Reset, color.Bold, color.FgBlack, color.BgHiYellow)
	case "error":
		level_color = color.New(color.Reset, color.Bold, color.FgBlack, color.BgHiRed)
	case "fatal":
		level_color = color.New(color.Reset, color.Bold, color.FgBlack, color.BgHiMagenta)
	default:
		level_color = color.New(color.Reset, color.Bold, color.FgBlack, color.BgHiMagenta)
	}

	fmt.Printf("%s %s%d%s ", time.Now().Format("15:04:05.000"), file, line, func_name)
	level_color.Printf("[%s]", level)
	fmt.Printf(" ")
	fmt.Printf(format, args...)
	fmt.Printf("\n")

}

package output

import (
	"fmt"
	"os"

	"github.com/fatih/color"
)

var (
	stdError = os.Stderr
)

func PrintLogo(noBanner bool) {
	green := color.New(color.FgHiGreen, color.Bold)
	asciiLogo := `
  _____ _    _ ______ _____ _  __ _____ ______ _____
 / ____| |  | |  ____/ ____| |/ // ____|  ____/ ____|
| |    | |__| | |__ | |    | ' /| (___ | |__ | |
| |    |  __  |  __|| |    |  <  \___ \|  __|| |
| |____| |  | | |___| |____| . \ ____) | |___| |____
 \_____|_|  |_|______\_____|_|\_\_____/|______\_____|
`
	if !noBanner {
		green.Println(asciiLogo)
	}
}

func ColorPrinter(result string, resultColor string) string {
	unset := color.New(color.Reset).SprintFunc()
	italic := color.New(color.Italic).SprintfFunc()
	red := color.New(color.FgRed).SprintFunc()
	green := color.New(color.FgGreen).SprintFunc()
	yellow := color.New(color.FgYellow).SprintFunc()
	blue := color.New(color.FgBlue).SprintFunc()

	if resultColor == "green" {
		return green(result)
	} else if resultColor == "red" {
		return red(result)
	} else if resultColor == "yellow" {
		return yellow(result)
	} else if resultColor == "blue" {
		return blue(result)
	} else if resultColor == "italic" {
		return italic(result)
	} else {
		return unset(result)
	}
}

func Fatalf(format string, a ...any) {
	fmt.Fprintf(stdError, format, a...)
	os.Exit(1)
}

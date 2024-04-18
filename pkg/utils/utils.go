package utils

import (
	"github.com/fatih/color"
)

func PrintLogo() {
	Red := color.New(color.FgHiRed, color.Bold)
	asciiLogo := `
_______           _______  _______  _        _______  _______  _______
(  ____ \|\     /|(  ____ \(  ____ \| \    /\(  ____ \(  ____ \(  ____ \
| (    \/| )   ( || (    \/| (    \/|  \  / /| (    \/| (    \/| (    \/
| |      | (___) || (__    | |      |  (_/ / | (_____ | (__    | |
| |      |  ___  ||  __)   | |      |   _ (  (_____  )|  __)   | |
| |      | (   ) || (      | |      |  ( \ \       ) || (      | |
| (____/\| )   ( || (____/\| (____/\|  /  \ \/\____) || (____/\| (____/\
(_______/|/     \|(_______/(_______/|_/    \/\_______)(_______/(_______/
`
	Red.Println(asciiLogo)
}

func colorPrinter(result string, resultColor string) string {
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

package main

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

// ANSI color codes
const (
	colorRed    = "\033[31m"
	colorCyan   = "\033[36m"
	colorDim    = "\033[2m"
	colorBold   = "\033[1m"
	colorReset  = "\033[0m"
)

const banner = `
  ______ ____ ______ __  __ _____
 /_  __//  _//_  __// / / // ___/
  / /   / /   / /  / / / / \__ \
 / /  _/ /   / /  / /_/ / ___/ /
/_/  /___/  /_/   \____/ /____/
`

const tagline = " Secrets hide. Titus finds."
const credit = " Praetorian Security, Inc."

func printBanner() {
	useColor := term.IsTerminal(int(os.Stderr.Fd()))

	if useColor {
		fmt.Fprintf(os.Stderr, "%s%s%s%s", colorBold, colorRed, banner, colorReset)
		fmt.Fprintf(os.Stderr, "%s%s%s\n", colorCyan, tagline, colorReset)
		fmt.Fprintf(os.Stderr, "%s%s%s\n\n", colorDim, credit, colorReset)
	} else {
		fmt.Fprint(os.Stderr, banner)
		fmt.Fprintln(os.Stderr, tagline)
		fmt.Fprintln(os.Stderr, credit)
		fmt.Fprintln(os.Stderr)
	}
}

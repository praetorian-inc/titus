//go:build wasm

package main

import (
	"syscall/js"
)

func main() {
	// Export functions to JavaScript
	js.Global().Set("TitusNewScanner", js.FuncOf(newScanner))
	js.Global().Set("TitusScan", js.FuncOf(scan))
	js.Global().Set("TitusScanBatch", js.FuncOf(scanBatch))
	js.Global().Set("TitusCloseScanner", js.FuncOf(closeScanner))
	js.Global().Set("TitusGetBuiltinRules", js.FuncOf(getBuiltinRules))

	// Keep WASM running
	<-make(chan struct{})
}

package main

import (
	"syscall/js"
	"strings"
)

func convertToExclamation(this js.Value, inputs []js.Value) interface{} {
	text := inputs[0].String()
	convertedText := strings.ReplaceAll(text, " ", "!")
	return js.ValueOf(convertedText)
}

func registerCallbacks() {
	js.Global().Set("convertToExclamation", js.FuncOf(convertToExclamation))
}

func main() {
	c := make(chan struct{}, 0)

	registerCallbacks()

	<-c
}

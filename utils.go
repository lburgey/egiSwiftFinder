package main

import (
	"os"
	"os/exec"
	"sort"

	"github.com/c-bata/go-prompt"
)

// go-prompt eats Ctrl+C if we don't do this, see: https://github.com/c-bata/go-prompt/issues/228#issuecomment-820639887
func fixTTY() {
	rawModeOff := exec.Command("/bin/stty", "-raw", "echo")
	rawModeOff.Stdin = os.Stdin
	_ = rawModeOff.Run()
	rawModeOff.Wait()
}

func selectString(choices []string) string {
	defer fixTTY()
	if len(choices) == 0 {
		return ""
	}

	sort.Strings(choices)
	completer := func(d prompt.Document) []prompt.Suggest {
		ss := make([]prompt.Suggest, len(choices))
		for i, s := range choices {
			ss[i] = prompt.Suggest{
				Text: s,
			}
		}
		return prompt.FilterHasPrefix(ss, d.GetWordBeforeCursor(), true)
	}
	options := []prompt.Option{
		prompt.OptionShowCompletionAtStart(),
		prompt.OptionCompletionOnDown(),
		prompt.OptionPrefix("> "),
	}
	choice := prompt.Input("", completer, options...)
	return choice
}

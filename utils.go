package main

import (
	"fmt"
	"sort"
	"strings"

	"github.com/c-bata/go-prompt"
	"github.com/jpillora/longestcommon"
)

func selectString(choices []string) string {
	if len(choices) == 0 {
		return ""
	}

	sort.Strings(choices)
	prefix := longestcommon.Prefix(choices)
	completer := func(d prompt.Document) []prompt.Suggest {
		ss := make([]prompt.Suggest, len(choices))
		for i, s := range choices {
			ss[i] = prompt.Suggest{
				Text: strings.TrimPrefix(s, prefix),
			}
		}
		return prompt.FilterHasPrefix(ss, d.GetWordBeforeCursor(), true)
	}
	options := []prompt.Option{
		prompt.OptionShowCompletionAtStart(),
		prompt.OptionCompletionOnDown(),
		// prompt.OptionInitialBufferText(prefix),
		prompt.OptionPrefix("> " + prefix),
	}
	choice := prompt.Input("", completer, options...)
	fmt.Printf("\n")
	return prefix + choice
}

package main

import (
	"bytes"
	"fmt"
	"sort"
	"text/template"

	"github.com/manifoldco/promptui"
)

func templateForSelected(kind string) string {
	return fmt.Sprintf(`{{ "%s" | green }} %s: {{ . | bold }}`, promptui.IconGood, kind)
}

func printWarn(errString string) {
	fmt.Printf("%s %s\n", promptui.IconWarn, errString)
}

func printError(errString string) {
	fmt.Printf("%s %s\n", promptui.IconBad, errString)
}

// printSelected prints in the same style as if we made a choice using selectString
// this is used when we determined that the user only has a single choice
func printSelected(kind string, choice string) (err error) {
	tpl, err := template.New("").Funcs(promptui.FuncMap).Parse(
		templateForSelected(kind),
	)
	if err != nil {
		return
	}
	var buf bytes.Buffer
	err = tpl.Execute(&buf, choice)
	if err != nil {
		return
	}
	fmt.Printf("%s\n", string(buf.Bytes()))
	return
}

func selectString(kind string, choices []string) (choice string, err error) {
	if len(choices) == 0 {
		err = fmt.Errorf("no choices provided")
		return
	}
	sort.Strings(choices)
	prompt := promptui.Select{
		Label: fmt.Sprintf("Select a %s", kind),
		Items: choices,
		Templates: &promptui.SelectTemplates{
			Selected: templateForSelected(kind),
		},
	}
	_, choice, err = prompt.Run()
	return
}

package utils

import (
	"bytes"
	"fmt"
	"sort"
	"text/template"

	"github.com/manifoldco/promptui"
)

type MessageType int

const (
	None MessageType = iota
	Good MessageType = iota
	Warn MessageType = iota
	Bad  MessageType = iota
)

var (
	IconGood = promptui.IconGood
	IconWarn = promptui.IconWarn
	IconBad  = promptui.IconBad
)

func getIcon(mt MessageType) (icon string) {
	if mt == Good {
		icon = promptui.IconGood
	} else if mt == Warn {
		icon = promptui.IconWarn
	} else if mt == Bad {
		icon = promptui.IconBad
	} else {
		icon = " "
	}

	return
}

func Print(mt MessageType, format string, a ...interface{}) {
	format = fmt.Sprintf("%s %s\n", getIcon(mt), format)
	fmt.Printf(format, a...)
}

func templateForSelected(kind string) string {
	return fmt.Sprintf(`%s %s: {{ . | bold }}`, IconGood, kind)
}

// printSelected prints in the same style as if we made a choice using selectString
// this is used when we determined that the user only has a single choice.
func PrintSelected(kind string, choice string) (err error) {
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

	fmt.Printf("%s\n", buf.String())

	return
}

func SelectString(kind string, choices []string) (choice string, err error) {
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

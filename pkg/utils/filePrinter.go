package utils

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"

	"github.com/slimm609/checksec/v3/pkg/output"
	"sigs.k8s.io/yaml"
)

type SecurityCheck struct {
	Name   string `json:"name"`
	Checks struct {
		Canary        string `json:"canary"`
		Fortified     string `json:"fortified"`
		FortifyAble   string `json:"fortifyable"`
		FortifySource string `json:"fortify_source"`
		NX            string `json:"nx"`
		PIE           string `json:"pie"`
		Relro         string `json:"relro"`
		RPath         string `json:"rpath"`
		RunPath       string `json:"runpath"`
		Symbols       string `json:"symbols"`
	} `json:"checks"`
}

type SecurityCheckColor struct {
	Name   string `json:"name"`
	Checks struct {
		Canary             string `json:"canary"`
		CanaryColor        string `json:"canaryColor"`
		Cfi                string `json:"cfi"`
		CfiColor           string `json:"cfiColor"`
		Fortified          string `json:"fortified"`
		FortifyAble        string `json:"fortifyable"`
		FortifySource      string `json:"fortify_source"`
		FortifySourceColor string `json:"fortify_sourceColor"`
		NX                 string `json:"nx"`
		NXColor            string `json:"nxColor"`
		PIE                string `json:"pie"`
		PIEColor           string `json:"pieColor"`
		Relro              string `json:"relro"`
		RelroColor         string `json:"relroColor"`
		RPath              string `json:"rpath"`
		RPathColor         string `json:"rpathColor"`
		RunPath            string `json:"runpath"`
		RunPathColor       string `json:"runpathColor"`
		Symbols            string `json:"symbols"`
		SymbolsColor       string `json:"symbolsColor"`
	} `json:"checks"`
}

func FilePrinter(outputFormat string, data interface{}, colors interface{}, noBanner bool, noHeader bool) {

	formatted, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		fmt.Printf("err: %v\n", err)
	}
	formattedcolor, err := json.MarshalIndent(colors, "", "  ")
	if err != nil {
		fmt.Printf("err: %v\n", err)
	}
	var securityChecks []SecurityCheck
	// Unmarshal JSON data
	if err := json.Unmarshal([]byte(formatted), &securityChecks); err != nil {
		fmt.Println("Error:", err)
		return
	}

	if outputFormat == "yaml" {
		yamlResponse, err := yaml.JSONToYAML(formatted)
		if err != nil {
			fmt.Printf("err: %v\n", err)
		}
		fmt.Println(string(yamlResponse))
	} else if outputFormat == "json" {
		fmt.Println(string(formatted))
	} else if outputFormat == "xml" {
		xmlData, err := xml.MarshalIndent(securityChecks, "", "  ")
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(string(xmlData))
	} else {
		output.PrintLogo(noBanner)
		var securityChecksColors []SecurityCheckColor

		// Unmarshal JSON data
		if err = json.Unmarshal([]byte(formattedcolor), &securityChecksColors); err != nil {
			fmt.Println("Error:", err)
			return
		}
		if !noHeader {
			fmt.Printf("%-24s%-26s%-26s%-22s%-24s%-19s%-21s%-24s%-19s%-20s%-25s%-40s\n",
				output.ColorPrinter("RELRO", "unset"),
				output.ColorPrinter("Stack Canary", "unset"),
				output.ColorPrinter("CFI", "unset"),
				output.ColorPrinter("NX", "unset"),
				output.ColorPrinter("PIE", "unset"),
				output.ColorPrinter("RPATH", "unset"),
				output.ColorPrinter("RUNPATH", "unset"),
				output.ColorPrinter("Symbols", "unset"),
				output.ColorPrinter("FORTIFY", "unset"),
				output.ColorPrinter("Fortified", "unset"),
				output.ColorPrinter("Fortifiable", "unset"),
				output.ColorPrinter("Name", "unset"),
			)
		}
		for _, check := range securityChecksColors {
			fmt.Printf("%-25s%-27s%-27s%-23s%-25s%-20s%-22s%-25s%-20s%-20s%-25s%-40s\n",
				output.ColorPrinter(check.Checks.Relro, check.Checks.RelroColor),
				output.ColorPrinter(check.Checks.Canary, check.Checks.CanaryColor),
				output.ColorPrinter(check.Checks.Cfi, check.Checks.CfiColor),
				output.ColorPrinter(check.Checks.NX, check.Checks.NXColor),
				output.ColorPrinter(check.Checks.PIE, check.Checks.PIEColor),
				output.ColorPrinter(check.Checks.RPath, check.Checks.RPathColor),
				output.ColorPrinter(check.Checks.RunPath, check.Checks.RunPathColor),
				output.ColorPrinter(check.Checks.Symbols, check.Checks.SymbolsColor),
				output.ColorPrinter(check.Checks.FortifySource, check.Checks.FortifySourceColor),
				output.ColorPrinter(check.Checks.Fortified, "unset"),
				output.ColorPrinter(check.Checks.FortifyAble, "unset"),
				output.ColorPrinter(check.Name, "unset"),
			)
		}
	}
}

package utils

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"

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
		PrintLogo(noBanner)
		var securityChecksColors []SecurityCheckColor

		// Unmarshal JSON data
		if err = json.Unmarshal([]byte(formattedcolor), &securityChecksColors); err != nil {
			fmt.Println("Error:", err)
			return
		}
		if !noHeader {
			fmt.Printf("%-24s%-26s%-22s%-24s%-19s%-21s%-24s%-19s%-20s%-25s%-40s\n",
				colorPrinter("RELRO", "unset"),
				colorPrinter("Stack Canary", "unset"),
				colorPrinter("NX", "unset"),
				colorPrinter("PIE", "unset"),
				colorPrinter("RPATH", "unset"),
				colorPrinter("RUNPATH", "unset"),
				colorPrinter("Symbols", "unset"),
				colorPrinter("FORTIFY", "unset"),
				colorPrinter("Fortified", "unset"),
				colorPrinter("Fortifiable", "unset"),
				colorPrinter("Name", "unset"),
			)
		}
		for _, check := range securityChecksColors {
			fmt.Printf("%-25s%-27s%-23s%-25s%-20s%-22s%-25s%-20s%-20s%-25s%-40s\n",
				colorPrinter(check.Checks.Relro, check.Checks.RelroColor),
				colorPrinter(check.Checks.Canary, check.Checks.CanaryColor),
				colorPrinter(check.Checks.NX, check.Checks.NXColor),
				colorPrinter(check.Checks.PIE, check.Checks.PIEColor),
				colorPrinter(check.Checks.RPath, check.Checks.RPathColor),
				colorPrinter(check.Checks.RunPath, check.Checks.RunPathColor),
				colorPrinter(check.Checks.Symbols, check.Checks.SymbolsColor),
				colorPrinter(check.Checks.FortifySource, check.Checks.FortifySourceColor),
				colorPrinter(check.Checks.Fortified, "unset"),
				colorPrinter(check.Checks.FortifyAble, "unset"),
				colorPrinter(check.Name, "unset"),
			)
		}
	}
}

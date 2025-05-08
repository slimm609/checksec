package utils

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"

	"sigs.k8s.io/yaml"
)

// FortifyCheck struct for non-colored data,
// keeping a dedicated struct allows conversion without removing the colors
type FortifyCheck struct {
	Name   string `json:"name"`
	Checks struct {
		Fortified     string `json:"fortified"`
		FortifyAble   string `json:"fortifyable"`
		FortifySource string `json:"fortify_source"`
		NoFortify     string `json:"noFortify"`
		LibcSupport   string `json:"libcSupport"`
		NumLibcFunc   string `json:"numLibcFunc"`
		NumFileFunc   string `json:"numFileFunc"`
	} `json:"checks"`
}

// FortifyCheckColor struct for colored data
type FortifyCheckColor struct {
	Name   string `json:"name"`
	Checks struct {
		Fortified          string `json:"fortified"`
		FortifyAble        string `json:"fortifyable"`
		FortifySource      string `json:"fortify_source"`
		FortifySourceColor string `json:"fortify_sourceColor"`
		NoFortify          string `json:"noFortify"`
		LibcSupport        string `json:"libcSupport"`
		LibcSupportColor   string `json:"libcSupportColor"`
		NumLibcFunc        string `json:"numLibcFunc"`
		NumFileFunc        string `json:"numFileFunc"`
	} `json:"checks"`
}

// FortifyPrinter - Print the output from FortifyFile function
func FortifyPrinter(outputFormat string, data interface{}, colors interface{}, noBanner bool, noHeader bool) {

	formatted, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		fmt.Printf("err: %v\n", err)
	}
	formattedcolor, err := json.MarshalIndent(colors, "", "  ")
	if err != nil {
		fmt.Printf("err: %v\n", err)
	}
	var fortifyChecks []FortifyCheck
	// Unmarshal JSON data
	if err := json.Unmarshal([]byte(formatted), &fortifyChecks); err != nil {
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
		xmlData, err := xml.MarshalIndent(fortifyChecks, "", "  ")
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(string(xmlData))
	} else {
		PrintLogo(noBanner)
		var fortifyChecksColors []FortifyCheckColor

		// Unmarshal JSON data
		if err = json.Unmarshal([]byte(formattedcolor), &fortifyChecksColors); err != nil {
			fmt.Println("Error:", err)
			return
		}

		for _, check := range fortifyChecksColors {
			fmt.Printf("* FORTIFY_SOURCE support available (libc): %s\n", colorPrinter(check.Checks.LibcSupport, check.Checks.LibcSupportColor))
			fmt.Printf("* Binary compiled with FORTIFY_SOURCE support: %s\n\n", colorPrinter(check.Checks.FortifySource, check.Checks.FortifySourceColor))
			fmt.Println("------ EXECUTABLE-FILE ------- | -------- LIBC --------")
			fmt.Println("Fortifiable library functions  | Checked function names")
			// TODO: add function breakdown
			fmt.Println("Coming Soon")
			fmt.Printf("\n%s\n", colorPrinter("SUMMARY", "green"))
			fmt.Printf("* Number of checked functions in libc                : %s\n", colorPrinter(check.Checks.NumLibcFunc, "unset"))
			fmt.Printf("* Total number of library functions in the executable: %s\n", colorPrinter(check.Checks.NumFileFunc, "unset"))
			fmt.Printf("* Number of Fortifiable functions in the executable  : %s\n", colorPrinter(check.Checks.FortifyAble, "unset"))
			fmt.Printf("* Number of checked functions in the executable      : %s\n", colorPrinter(check.Checks.Fortified, "green"))
			fmt.Printf("* Number of unchecked functions in the executable    : %s\n", colorPrinter(check.Checks.NoFortify, "red"))
		}
	}
}

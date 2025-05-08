package utils

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"

	"sigs.k8s.io/yaml"
)

type KernelCheckColor struct {
	Name        string `json:"name"`
	Description string `json:"desc"`
	Color       string `json:"color"`
	Value       string `json:"value"`
	CheckType   string `json:"type"`
}

type KernelCheck struct {
	Name        string `json:"name"`
	Description string `json:"desc"`
	Value       string `json:"value"`
	CheckType   string `json:"type"`
}

func KernelPrinter(outputFormat string, kernel any, kernelColors any, noBanner bool, noHeader bool) {

	formattedKernel, err := json.MarshalIndent(kernel, "", "  ")
	if err != nil {
		fmt.Printf("err: %v\n", err)
	}

	formattedKernelColors, err := json.MarshalIndent(kernelColors, "", "  ")
	if err != nil {
		fmt.Printf("err: %v\n", err)
	}

	var KernelCheck []KernelCheck
	// Unmarshal JSON data
	if err := json.Unmarshal([]byte(formattedKernel), &KernelCheck); err != nil {
		fmt.Println("Error:", err)
		return
	}

	var KernelCheckColor []KernelCheckColor
	// Unmarshal JSON data
	if err := json.Unmarshal([]byte(formattedKernelColors), &KernelCheckColor); err != nil {
		fmt.Println("Error:", err)
		return
	}

	if outputFormat == "yaml" {
		yamlResponse, err := yaml.JSONToYAML(formattedKernel)
		if err != nil {
			fmt.Printf("err: %v\n", err)
		}
		fmt.Println(string(yamlResponse))
	} else if outputFormat == "json" {
		fmt.Println(string(formattedKernel))
	} else if outputFormat == "xml" {
		xmlData, err := xml.MarshalIndent(KernelCheck, "", "  ")
		if err != nil {
			log.Fatal(err)
		}
		fmt.Println(string(xmlData))
	} else {
		PrintLogo(noBanner)
		if !noHeader {
			fmt.Println("Kernel configs only print what is supported by the specific kernel/kernel config")
			fmt.Printf("%-70s%-25s%-30s%-30s\n",
				colorPrinter("Description", "unset"),
				colorPrinter("Value", "unset"),
				colorPrinter("Check Type", "unset"),
				colorPrinter("Config Key", "unset"),
			)
		}
		for _, check := range KernelCheckColor {
			fmt.Printf("%-70s%-26s%-30s%-30s\n",
				colorPrinter(check.Description, "unset"),
				colorPrinter(check.Value, check.Color),
				colorPrinter(check.CheckType, "unset"),
				colorPrinter(check.Name, "unset"),
			)
		}
	}

}

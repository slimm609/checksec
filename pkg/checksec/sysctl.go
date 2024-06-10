package checksec

import (
	"runtime"

	"github.com/lorenzosaino/go-sysctl"
)

func SysctlCheck() ([]interface{}, []interface{}) {
	var Results []interface{}
	var ColorResults []interface{}

	sysctlChecks := []map[string]interface{}{
		{"name": "fs.protected_symlinks", "desc": "Protected symlinks", "values": map[string]map[string]string{"0": {"res": "Disabled", "color": "red"}, "1": {"res": "Enabled", "color": "green"}}},
		{"name": "fs.protected_hardlinks", "desc": "Protected hardlinks", "values": map[string]map[string]string{"0": {"res": "Disabled", "color": "red"}, "1": {"res": "Enabled", "color": "green"}}},
		{"name": "net.ipv4.conf.all.rp_filter", "desc": "Ipv4 reverse path filtering", "values": map[string]map[string]string{"0": {"res": "Disabled", "color": "red"}, "1": {"res": "Enabled", "color": "green"}}},
		{"name": "kernel.yama.ptrace_scope", "desc": "YAMA", "values": map[string]map[string]string{"0": {"res": "Disabled", "color": "red"}, "1": {"res": "Enabled", "color": "green"}}},
		{"name": "kernel.exec-shield", "desc": "Exec Shield", "values": map[string]map[string]string{"0": {"res": "Disabled", "color": "red"}, "1": {"res": "Enabled", "color": "green"}}},
		{"name": "kernel.randomize_va_space", "desc": "Vanilla Kernel ASLR", "values": map[string]map[string]string{"0": {"res": "Disabled", "color": "red"}, "1": {"res": "Partial", "color": "yellow"}, "2": {"res": "Enabled", "color": "green"}}},
		{"name": "fs.protected_fifos", "desc": "Protected fifos", "values": map[string]map[string]string{"0": {"res": "Disabled", "color": "red"}, "1": {"res": "Partial", "color": "yellow"}, "2": {"res": "Enabled", "color": "green"}}},
		{"name": "fs.protected_regular", "desc": "Protected regular", "values": map[string]map[string]string{"0": {"res": "Disabled", "color": "red"}, "1": {"res": "Partial", "color": "yellow"}, "2": {"res": "Enabled", "color": "green"}}},
	}

	for _, s := range sysctlChecks {
		var res []interface{}
		var colors []interface{}
		var output string
		var color string
		check, _ := sysctl.Get(s["name"].(string))

		values := s["values"].(map[string]map[string]string)

		if len(check) == 0 {
			if runtime.GOOS == "linux" {
				output = "Unknown"
			} else {
				output = "N/A"
			}
			color = "italic"
		} else {
			output = values[check]["res"]
			color = values[check]["color"]
		}
		res = []interface{}{
			map[string]interface{}{
				"name":  s["name"],
				"value": output,
				"desc":  s["desc"],
				"type":  "Sysctl",
			},
		}
		colors = []interface{}{
			map[string]interface{}{
				"name":  s["name"],
				"value": output,
				"color": color,
				"desc":  s["desc"],
				"type":  "Sysctl",
			},
		}
		Results = append(Results, res...)
		ColorResults = append(ColorResults, colors...)
	}

	return Results, ColorResults
}

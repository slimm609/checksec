package checksec

// Status is the severity of a check result. The string values are the colour
// names already understood by output.ColorPrinter, so a Status can be passed
// straight through to the renderer.
type Status string

const (
	StatusGood  Status = "green"
	StatusWarn  Status = "yellow"
	StatusBad   Status = "red"
	StatusInfo  Status = "unset"
	StatusNA    Status = "italic"
	StatusError Status = "red"
)

// Result is the uniform return shape for every binary check. All output
// formats (table, JSON, YAML, XML) render from this single type, so adding a
// new check requires no changes to the printers.
type Result struct {
	Value  string `json:"value"  xml:",chardata" yaml:"value"`
	Status Status `json:"status" xml:"status,attr" yaml:"status"`
}

// Err produces a Result representing a check that failed to run.
func Err(check string) Result {
	return Result{Value: "Error checking " + check, Status: StatusError}
}

// KernelCheck is the uniform result for one kernel-config / sysctl / LSM check.
// All printers (table, JSON, YAML, XML) render directly from this type.
type KernelCheck struct {
	Name   string `json:"name"   xml:"name,attr"   yaml:"name"`
	Desc   string `json:"desc"   xml:"desc,attr"   yaml:"desc"`
	Type   string `json:"type"   xml:"type,attr"   yaml:"type"`
	Result Result `json:"result" xml:"result"      yaml:"result"`
}

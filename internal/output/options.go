package output

type OutputFormat string

type FormatterOptions struct {
	Format      OutputFormat
	ColorOutput bool
	Quiet       bool
	Verbose     bool
	Indent      string
}

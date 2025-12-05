package heuristics

// EnhancedPackageFeatures represents features for ML analysis
type EnhancedPackageFeatures struct {
	PackageName      string
	Registry         string
	Maintainers      []string
	Dependencies     []Dependency
	Files            []string
	Readme           string
	Downloads        int64
	Stars            int
	Forks            int
	CreatedAt        int64
	UpdatedAt        int64
	HasLicense       bool
	HasTests         bool
	HasCI            bool
	HasDocumentation bool
}

// Dependency represents a dependency for ML analysis
type Dependency struct {
	Name    string
	Version string
}

// MLDetectionResult represents the result of ML analysis
type MLDetectionResult struct {
	Score       float64
	Confidence  float64
	RiskLevel   string
	Threats     []string
	Anomalies   []string
	Explanation string
}

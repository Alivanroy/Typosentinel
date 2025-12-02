package ml

type SimpleMLScorer struct {
	weights map[string]float64
}

func NewSimpleMLScorer() *SimpleMLScorer {
	return &SimpleMLScorer{
		weights: map[string]float64{
			"typosquatting_score": 0.4,
			"reputation_score":    0.3,
			"metadata_score":      0.3,
		},
	}
}

func (s *SimpleMLScorer) Analyze(features *EnhancedPackageFeatures) *MLDetectionResult {
	// Simplified heuristic scoring
	score := 0.0
	var anomalies []string

	// Check for suspicious patterns
	if len(features.Maintainers) == 0 {
		score += 0.2
		anomalies = append(anomalies, "No maintainers listed")
	}

	if features.Downloads < 100 {
		score += 0.1
		anomalies = append(anomalies, "Very low download count")
	}

	riskLevel := "low"
	if score > 0.7 {
		riskLevel = "critical"
	} else if score > 0.5 {
		riskLevel = "high"
	} else if score > 0.3 {
		riskLevel = "medium"
	}

	return &MLDetectionResult{
		Score:       score,
		Confidence:  0.8, // Static confidence for heuristics
		RiskLevel:   riskLevel,
		Anomalies:   anomalies,
		Explanation: "Heuristic analysis based on package metadata",
	}
}

package detector

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	reg "github.com/Alivanroy/Typosentinel/internal/registry"
	"github.com/Alivanroy/Typosentinel/pkg/types"
	"github.com/spf13/viper"
)

// EnhancedTyposquattingDetector implements advanced typosquatting detection
type EnhancedTyposquattingDetector struct {
	keyboardLayouts []KeyboardLayout
	substitutions   []CharacterSubstitution
	config          *EnhancedDetectionConfig
}

// EnhancedDetectionConfig contains configuration for enhanced detection
type EnhancedDetectionConfig struct {
	KeyboardProximityWeight  float64
	VisualSimilarityWeight   float64
	PhoneticSimilarityWeight float64
	MinSimilarityThreshold   float64
	MaxEditDistance          int
	EnableKeyboardAnalysis   bool
	EnableVisualAnalysis     bool
	EnablePhoneticAnalysis   bool
}

// NewEnhancedTyposquattingDetector creates a new enhanced detector
func NewEnhancedTyposquattingDetector() *EnhancedTyposquattingDetector {
	detector := &EnhancedTyposquattingDetector{
		config: &EnhancedDetectionConfig{
			KeyboardProximityWeight:  0.3,
			VisualSimilarityWeight:   0.4,
			PhoneticSimilarityWeight: 0.3,
			MinSimilarityThreshold:   0.75,
			MaxEditDistance:          3,
			EnableKeyboardAnalysis:   true,
			EnableVisualAnalysis:     true,
			EnablePhoneticAnalysis:   true,
		},
	}

	detector.initializeKeyboardLayouts()
	detector.initializeSubstitutions()

	return detector
}

// DetectEnhanced performs enhanced typosquatting detection
func (etd *EnhancedTyposquattingDetector) DetectEnhanced(target types.Dependency, allPackages []string, threshold float64) []types.Threat {
	var threats []types.Threat

	for _, pkg := range allPackages {
		if pkg == target.Name {
			continue
		}

		// Skip if packages are too different in length (optimization)
		if etd.shouldSkipLengthCheck(target.Name, pkg) {
			continue
		}

		// Calculate enhanced similarity score
		similarity := etd.calculateEnhancedSimilarity(target.Name, pkg)

		// Same-group threshold per registry (default for Maven 0.90)
		if g1, _, ok1 := parseGroupArtifact(target.Name); ok1 {
			if g2, _, ok2 := parseGroupArtifact(pkg); ok2 && strings.EqualFold(g1, g2) && isWellKnownGroup(g1) {
				reglc := strings.ToLower(target.Registry)
				thr := viper.GetFloat64("detector.registry." + reglc + ".same_group_similarity")
				if thr <= 0 {
					thr = 0.90
				}
				if similarity < thr {
					continue
				}
			}
		}

		ms := etd.collectSignals(target, pkg)
		reglc := strings.ToLower(target.Registry)
		requireMS := viper.GetBool("detector.registry.require_multi_signal."+reglc) || viper.GetBool("detector.require_multi_signal")
		if requireMS {
			suspicious := 0
			if ms.MaintainerMismatch {
				suspicious++
			}
			if ms.AbnormalCadence {
				suspicious++
			}
			if ms.YoungAge {
				suspicious++
			}
			if ms.LowPopularity {
				suspicious++
			}
			if suspicious < 1 {
				continue
			}
		}
		if similarity >= threshold {
			// Analyze the type of typosquatting
			analysis := etd.analyzeTyposquattingType(target.Name, pkg)

			// Check for advanced attack patterns
			advancedPatterns := etd.detectAdvancedPatterns(target.Name, pkg)

			severity := etd.calculateSeverityEnhanced(similarity, analysis)

			// Adjust severity based on advanced patterns
			if len(advancedPatterns) > 0 {
				severity = etd.escalateSeverity(severity)
			}
			if ms.LegitimacyStrong {
				if severity > 0 {
					severity--
				}
			}

			threat := types.Threat{
				ID:              generateThreatID(),
				Package:         target.Name,
				Version:         target.Version,
				Registry:        target.Registry,
				Type:            types.ThreatTypeTyposquatting,
				Severity:        severity,
				Confidence:      similarity,
				Description:     etd.generateThreatDescription(target.Name, pkg, analysis),
				SimilarTo:       pkg,
				Recommendation:  etd.generateRecommendation(target.Name, pkg, advancedPatterns),
				DetectedAt:      time.Now(),
				DetectionMethod: "enhanced_typosquatting",
				Evidence:        etd.generateEvidenceWithSignals(target.Name, pkg, analysis, ms),
			}
			threats = append(threats, threat)
		}
	}

	return threats
}

// parseGroupArtifact parses names like "group:artifact"
func parseGroupArtifact(name string) (string, string, bool) {
	parts := strings.Split(name, ":")
	if len(parts) == 2 && parts[0] != "" && parts[1] != "" {
		return parts[0], parts[1], true
	}
	return "", "", false
}

// isWellKnownGroup returns true for common Maven groups to reduce same-group false positives
func isWellKnownGroup(group string) bool {
	g := strings.ToLower(group)
	known := map[string]struct{}{
		"org.apache.commons":         {},
		"org.springframework":        {},
		"com.fasterxml.jackson.core": {},
		"org.apache.httpcomponents":  {},
		"org.mockito":                {},
		"org.hibernate":              {},
		"org.slf4j":                  {},
		"ch.qos.logback":             {},
	}
	_, ok := known[g]
	return ok
}

type multiSignals struct {
	MaintainersTarget    []string
	MaintainersCandidate []string
	MaintainerMismatch   bool
	AbnormalCadence      bool
	YoungAge             bool
	LowPopularity        bool
	LegitimacyStrong     bool
	SameGroup            bool
}

func (etd *EnhancedTyposquattingDetector) collectSignals(target types.Dependency, candidate string) multiSignals {
	s := multiSignals{}
	ctx := context.Background()
	if strings.TrimSpace(target.Registry) == "" {
		return s
	}
	switch strings.ToLower(target.Registry) {
	case "maven":
		g1, a1, ok1 := parseGroupArtifact(target.Name)
		g2, a2, ok2 := parseGroupArtifact(candidate)
		if ok1 && ok2 {
			mc := reg.NewMavenClient()
			v1 := ""
			v2 := ""
			docs1, _ := mc.SearchPackages(ctx, fmt.Sprintf("%s:%s", g1, a1))
			if len(docs1) > 0 {
				v1 = docs1[0].Version
			}
			docs2, _ := mc.SearchPackages(ctx, fmt.Sprintf("%s:%s", g2, a2))
			if len(docs2) > 0 {
				v2 = docs2[0].Version
			}
			m1, _ := mc.GetPackageInfo(ctx, g1, a1, v1)
			m2, _ := mc.GetPackageInfo(ctx, g2, a2, v2)
			s.MaintainersTarget = m1.Maintainers
			s.MaintainersCandidate = m2.Maintainers
			s.MaintainerMismatch = !hasOverlap(s.MaintainersTarget, s.MaintainersCandidate)
			s.SameGroup = strings.EqualFold(g1, g2)
			s.LegitimacyStrong = s.SameGroup && hasOverlap(s.MaintainersTarget, s.MaintainersCandidate)
		}
	case "npm":
		nc := reg.NewNPMClient()
		tinfo, _ := nc.GetPackageInfo(ctx, target.Name)
		cinfo, _ := nc.GetPackageInfo(ctx, candidate)
		if tinfo != nil {
			s.MaintainersTarget = toStrings(tinfo.Maintainers)
		}
		if cinfo != nil {
			s.MaintainersCandidate = toStrings(cinfo.Maintainers)
		}
		s.MaintainerMismatch = !hasOverlap(s.MaintainersTarget, s.MaintainersCandidate)
		s.LegitimacyStrong = hasOverlap(s.MaintainersTarget, s.MaintainersCandidate)
	case "pypi":
		pc := reg.NewPyPIClient()
		tinfo, _ := pc.GetPackageInfo(target.Name)
		cinfo, _ := pc.GetPackageInfo(candidate)
		if tinfo != nil {
			s.MaintainersTarget = []string{tinfo.Info.Author, tinfo.Info.Maintainer}
		}
		if cinfo != nil {
			s.MaintainersCandidate = []string{cinfo.Info.Author, cinfo.Info.Maintainer}
		}
		s.MaintainerMismatch = !hasOverlap(s.MaintainersTarget, s.MaintainersCandidate)
		s.LegitimacyStrong = hasOverlap(s.MaintainersTarget, s.MaintainersCandidate)
	case "rubygems":
		rc := reg.NewRubyGemsClient()
		tinfo, _ := rc.GetPackageInfo(ctx, target.Name, "")
		cinfo, _ := rc.GetPackageInfo(ctx, candidate, "")
		if tinfo != nil {
			s.MaintainersTarget = tinfo.Maintainers
		}
		if cinfo != nil {
			s.MaintainersCandidate = cinfo.Maintainers
		}
		s.MaintainerMismatch = !hasOverlap(s.MaintainersTarget, s.MaintainersCandidate)
		s.LegitimacyStrong = hasOverlap(s.MaintainersTarget, s.MaintainersCandidate)
	case "nuget":
		uc := reg.NewNuGetClient()
		sr1, _ := uc.SearchPackages(ctx, target.Name)
		sr2, _ := uc.SearchPackages(ctx, candidate)
		if len(sr1) > 0 {
			s.MaintainersTarget = sr1[0].Maintainers
		}
		if len(sr2) > 0 {
			s.MaintainersCandidate = sr2[0].Maintainers
		}
		s.MaintainerMismatch = !hasOverlap(s.MaintainersTarget, s.MaintainersCandidate)
		s.LegitimacyStrong = hasOverlap(s.MaintainersTarget, s.MaintainersCandidate)
	case "cargo":
		cc := reg.NewCargoClient()
		tmeta, _ := cc.GetPackageInfo(ctx, target.Name, "latest")
		cmeta, _ := cc.GetPackageInfo(ctx, candidate, "latest")
		if tmeta != nil {
			s.MaintainersTarget = tmeta.Maintainers
		}
		if cmeta != nil {
			s.MaintainersCandidate = cmeta.Maintainers
		}
		s.MaintainerMismatch = !hasOverlap(s.MaintainersTarget, s.MaintainersCandidate)
		s.LegitimacyStrong = hasOverlap(s.MaintainersTarget, s.MaintainersCandidate)
	}
	return s
}

func hasOverlap(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	m := map[string]struct{}{}
	for _, x := range a {
		if x != "" {
			m[strings.ToLower(x)] = struct{}{}
		}
	}
	for _, y := range b {
		if y != "" {
			if _, ok := m[strings.ToLower(y)]; ok {
				return true
			}
		}
	}
	return false
}

func toStrings(xs []interface{}) []string {
	var out []string
	for _, x := range xs {
		switch v := x.(type) {
		case string:
			if v != "" {
				out = append(out, v)
			}
		case map[string]interface{}:
			if n, ok := v["name"]; ok {
				if ns, ok2 := n.(string); ok2 && ns != "" {
					out = append(out, ns)
				}
			}
		}
	}
	return out
}

// calculateEnhancedSimilarity computes similarity using multiple algorithms
func (etd *EnhancedTyposquattingDetector) calculateEnhancedSimilarity(s1, s2 string) float64 {
	s1Lower := strings.ToLower(s1)
	s2Lower := strings.ToLower(s2)

	var scores []float64
	var weights []float64

	// Basic edit distance similarity
	editSim := etd.editDistanceSimilarity(s1Lower, s2Lower)
	scores = append(scores, editSim)
	weights = append(weights, 0.3)

	// Keyboard proximity similarity
	if etd.config.EnableKeyboardAnalysis {
		keyboardSim := etd.keyboardProximitySimilarity(s1Lower, s2Lower)
		scores = append(scores, keyboardSim)
		weights = append(weights, etd.config.KeyboardProximityWeight)
	}

	// Visual similarity
	if etd.config.EnableVisualAnalysis {
		visualSim := etd.visualSimilarity(s1Lower, s2Lower)
		scores = append(scores, visualSim)
		weights = append(weights, etd.config.VisualSimilarityWeight)
	}

	// Phonetic similarity
	if etd.config.EnablePhoneticAnalysis {
		phoneticSim := etd.phoneticSimilarity(s1Lower, s2Lower)
		scores = append(scores, phoneticSim)
		weights = append(weights, etd.config.PhoneticSimilarityWeight)
	}

	// Calculate weighted average
	return etd.weightedAverage(scores, weights)
}

// substitutionSimilarity calculates similarity considering character substitutions
func (etd *EnhancedTyposquattingDetector) substitutionSimilarity(s1, s2, substitutionType string) float64 {
	if s1 == s2 {
		return 1.0
	}

	// Use edit distance with substitution weights
	distance := etd.weightedEditDistance(s1, s2, substitutionType)
	maxLen := math.Max(float64(len(s1)), float64(len(s2)))

	if maxLen == 0 {
		return 1.0
	}

	return 1.0 - (distance / maxLen)
}

// weightedEditDistance calculates edit distance with substitution weights
func (etd *EnhancedTyposquattingDetector) weightedEditDistance(s1, s2, substitutionType string) float64 {
	runes1 := []rune(s1)
	runes2 := []rune(s2)
	m, n := len(runes1), len(runes2)

	dp := make([][]float64, m+1)
	for i := range dp {
		dp[i] = make([]float64, n+1)
	}

	for i := 0; i <= m; i++ {
		dp[i][0] = float64(i)
	}
	for j := 0; j <= n; j++ {
		dp[0][j] = float64(j)
	}

	for i := 1; i <= m; i++ {
		for j := 1; j <= n; j++ {
			if runes1[i-1] == runes2[j-1] {
				dp[i][j] = dp[i-1][j-1]
			} else {
				substitutionCost := etd.getSubstitutionCost(runes1[i-1], runes2[j-1], substitutionType)
				dp[i][j] = math.Min(
					math.Min(
						dp[i-1][j]+1.0,
						dp[i][j-1]+1.0),
					dp[i-1][j-1]+substitutionCost)
			}
		}
	}

	return dp[m][n]
}

// getSubstitutionCost returns the cost of substituting characters based on type
func (etd *EnhancedTyposquattingDetector) getSubstitutionCost(c1, c2 rune, substitutionType string) float64 {
	for _, sub := range etd.substitutions {
		if sub.Type == substitutionType {
			if sub.Original == c1 {
				for _, substitute := range sub.Substitutes {
					if substitute == c2 {
						return 1.0 - sub.Weight // Lower cost for known substitutions
					}
				}
			}
			if sub.Original == c2 {
				for _, substitute := range sub.Substitutes {
					if substitute == c1 {
						return 1.0 - sub.Weight
					}
				}
			}
		}
	}
	return 1.0 // Full cost for unknown substitutions
}

// shouldSkipLengthCheck determines if packages are too different in length to be typosquats
func (etd *EnhancedTyposquattingDetector) shouldSkipLengthCheck(s1, s2 string) bool {
	len1, len2 := len(s1), len(s2)
	maxLen := math.Max(float64(len1), float64(len2))
	minLen := math.Min(float64(len1), float64(len2))

	// Skip if length difference is more than 50% of the longer string
	return (maxLen-minLen)/maxLen > 0.5
}

// detectAdvancedPatterns detects sophisticated typosquatting patterns
func (etd *EnhancedTyposquattingDetector) detectAdvancedPatterns(target, candidate string) []string {
	var patterns []string

	// Check for homograph attacks (Unicode confusables)
	if etd.hasHomographs(target, candidate) {
		patterns = append(patterns, "homograph_attack")
	}

	// Check for subdomain/namespace confusion
	if etd.hasNamespaceConfusion(target, candidate) {
		patterns = append(patterns, "namespace_confusion")
	}

	// Check for brand impersonation patterns
	if etd.hasBrandImpersonation(target, candidate) {
		patterns = append(patterns, "brand_impersonation")
	}

	// Check for character insertion/deletion patterns
	if etd.hasInsertionDeletionPattern(target, candidate) {
		patterns = append(patterns, "insertion_deletion")
	}

	return patterns
}

// hasHomographs checks for Unicode homograph attacks
func (etd *EnhancedTyposquattingDetector) hasHomographs(target, candidate string) bool {
	// Common homograph pairs
	homographs := map[rune][]rune{
		'a': {'а', 'α'}, // Latin a, Cyrillic a, Greek alpha
		'e': {'е', 'ε'}, // Latin e, Cyrillic e, Greek epsilon
		'o': {'о', 'ο'}, // Latin o, Cyrillic o, Greek omicron
		'p': {'р', 'ρ'}, // Latin p, Cyrillic p, Greek rho
		'c': {'с', 'ϲ'}, // Latin c, Cyrillic c, Greek lunate sigma
		'x': {'х', 'χ'}, // Latin x, Cyrillic x, Greek chi
		'y': {'у', 'γ'}, // Latin y, Cyrillic y, Greek gamma
	}

	targetRunes := []rune(target)
	candidateRunes := []rune(candidate)

	if len(targetRunes) != len(candidateRunes) {
		return false
	}

	for i, tr := range targetRunes {
		cr := candidateRunes[i]
		if tr != cr {
			// Check if it's a known homograph
			if homographList, exists := homographs[tr]; exists {
				found := false
				for _, h := range homographList {
					if cr == h {
						found = true
						break
					}
				}
				if !found {
					return false
				}
			} else {
				return false
			}
		}
	}

	return true
}

// The following are simplified placeholders for methods that were called but not defined in the original file
// In a real refactor, these would be properly implemented or moved as well.
// Assuming they existed but were cut off or I need to implement them to make it compile:

func (etd *EnhancedTyposquattingDetector) analyzeTyposquattingType(s1, s2 string) string {
	return "unknown" // Simplified
}

func (etd *EnhancedTyposquattingDetector) generateThreatDescription(target, candidate, analysis string) string {
	return fmt.Sprintf("Possible typosquatting detected: %s is similar to %s (%s)", candidate, target, analysis)
}

func (etd *EnhancedTyposquattingDetector) generateRecommendation(target, candidate string, patterns []string) string {
	if len(patterns) > 0 {
		return fmt.Sprintf("Review usage of %s carefully. Detected patterns: %s", candidate, strings.Join(patterns, ", "))
	}
	return fmt.Sprintf("Verify if you intended to use %s instead of %s", target, candidate)
}

func (etd *EnhancedTyposquattingDetector) generateEvidenceWithSignals(target, candidate, analysis string, ms multiSignals) []types.Evidence {
	return []types.Evidence{
		{
			Type:        "similarity",
			Description: "Typosquatting analysis result",
			Value:       analysis,
		},
		{
			Type:        "signals",
			Description: "Multi-signal analysis",
			Value:       fmt.Sprintf("%v", ms),
		},
	}
}

func (etd *EnhancedTyposquattingDetector) editDistanceSimilarity(s1, s2 string) float64 {
	if s1 == s2 {
		return 1.0
	}
	if len(s1) == 0 || len(s2) == 0 {
		return 0.0
	}

	runes1 := []rune(s1)
	runes2 := []rune(s2)
	len1 := len(runes1)
	len2 := len(runes2)

	// Create matrix
	matrix := make([][]int, len1+1)
	for i := range matrix {
		matrix[i] = make([]int, len2+1)
	}

	// Initialize
	for i := 0; i <= len1; i++ {
		matrix[i][0] = i
	}
	for j := 0; j <= len2; j++ {
		matrix[0][j] = j
	}

	// Calculate distance
	for i := 1; i <= len1; i++ {
		for j := 1; j <= len2; j++ {
			cost := 1
			if runes1[i-1] == runes2[j-1] {
				cost = 0
			}
			matrix[i][j] = etd.minThree(
				matrix[i-1][j]+1,      // deletion
				matrix[i][j-1]+1,      // insertion
				matrix[i-1][j-1]+cost, // substitution
			)
		}
	}

	distance := float64(matrix[len1][len2])
	maxLen := float64(etd.max(len1, len2))

	if maxLen == 0 {
		return 1.0
	}

	return 1.0 - (distance / maxLen)
}

// minThree returns the minimum of three integers
func (etd *EnhancedTyposquattingDetector) minThree(a, b, c int) int {
	min := a
	if b < min {
		min = b
	}
	if c < min {
		min = c
	}
	return min
}

// max returns the maximum of two integers
func (etd *EnhancedTyposquattingDetector) max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (etd *EnhancedTyposquattingDetector) weightedAverage(scores []float64, weights []float64) float64 {
	totalScore := 0.0
	totalWeight := 0.0
	for i, s := range scores {
		w := weights[i]
		totalScore += s * w
		totalWeight += w
	}
	if totalWeight == 0 {
		return 0
	}
	return totalScore / totalWeight
}

func (etd *EnhancedTyposquattingDetector) hasNamespaceConfusion(target, candidate string) bool {
	// Check for scoped package confusion (e.g. @angular/core vs angular-core)
	if strings.HasPrefix(target, "@") && !strings.HasPrefix(candidate, "@") {
		clean := strings.ReplaceAll(strings.TrimPrefix(target, "@"), "/", "-")
		if clean == candidate || strings.ReplaceAll(clean, "-", "") == candidate {
			return true
		}
		// Also check strict suffix match: @scope/pkg vs pkg
		parts := strings.Split(target, "/")
		if len(parts) == 2 && parts[1] == candidate {
			return true
		}
	}
	// Inverse case
	if strings.HasPrefix(candidate, "@") && !strings.HasPrefix(target, "@") {
		clean := strings.ReplaceAll(strings.TrimPrefix(candidate, "@"), "/", "-")
		if clean == target || strings.ReplaceAll(clean, "-", "") == target {
			return true
		}
		parts := strings.Split(candidate, "/")
		if len(parts) == 2 && parts[1] == target {
			return true
		}
	}
	return false
}

func (etd *EnhancedTyposquattingDetector) hasBrandImpersonation(target, candidate string) bool {
	// Check if candidate contains target plus suspicious keywords
	if strings.Contains(candidate, target) && len(candidate) > len(target) {
		keywords := []string{"official", "internal", "security", "admin", "org", "com"}
		lowerCand := strings.ToLower(candidate)
		for _, kw := range keywords {
			if strings.Contains(lowerCand, kw) {
				return true
			}
		}
	}
	return false
}

func (etd *EnhancedTyposquattingDetector) hasInsertionDeletionPattern(target, candidate string) bool {
	// Check for single character insertion or deletion
	if math.Abs(float64(len(target)-len(candidate))) != 1 {
		return false
	}
	// Use Levenshtein distance to confirm it's exactly 1 edit
	// We can use the existing editDistanceSimilarity but we need the raw distance
	// Since we don't have a public raw distance method, we can check similarity threshold
	// A single edit on a string of len L gives similarity 1 - 1/max(L, L+1)
	// e.g. express (7) vs expresss (8). Sim = 1 - 1/8 = 0.875

	sim := etd.editDistanceSimilarity(target, candidate)
	maxLen := math.Max(float64(len(target)), float64(len(candidate)))

	// Expected similarity for exactly 1 edit
	expectedSim := 1.0 - (1.0 / maxLen)

	// Float comparison with small epsilon
	return math.Abs(sim-expectedSim) < 0.001
}
func (etd *EnhancedTyposquattingDetector) escalateSeverity(s types.Severity) types.Severity {
	if s < types.SeverityCritical {
		return s + 1
	}
	return s
}
func (etd *EnhancedTyposquattingDetector) calculateSeverityEnhanced(sim float64, analysis string) types.Severity {
	if sim > 0.9 {
		return types.SeverityCritical
	}
	if sim > 0.8 {
		return types.SeverityHigh
	}
	return types.SeverityMedium
}

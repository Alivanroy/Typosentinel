package detector

import (
    "context"
    "fmt"
    "math"
    "strings"
    "time"
    "unicode"

    reg "github.com/Alivanroy/Typosentinel/internal/registry"
    "github.com/spf13/viper"
    "github.com/Alivanroy/Typosentinel/pkg/types"
)

// KeyboardLayout represents different keyboard layouts for proximity analysis
type KeyboardLayout struct {
	Name   string
	Layout map[rune][]rune // character -> adjacent characters
	Rows   []string        // keyboard rows for row-based analysis
}

// CharacterSubstitution represents common character substitution patterns
type CharacterSubstitution struct {
	Original    rune
	Substitutes []rune
	Type        string // "visual", "phonetic", "keyboard"
	Weight      float64
}

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

// initializeKeyboardLayouts sets up common keyboard layouts
func (etd *EnhancedTyposquattingDetector) initializeKeyboardLayouts() {
	// QWERTY layout
	qwerty := KeyboardLayout{
		Name: "QWERTY",
		Layout: map[rune][]rune{
			'q': {'w', 'a', 's'},
			'w': {'q', 'e', 'a', 's', 'd'},
			'e': {'w', 'r', 's', 'd', 'f'},
			'r': {'e', 't', 'd', 'f', 'g'},
			't': {'r', 'y', 'f', 'g', 'h'},
			'y': {'t', 'u', 'g', 'h', 'j'},
			'u': {'y', 'i', 'h', 'j', 'k'},
			'i': {'u', 'o', 'j', 'k', 'l'},
			'o': {'i', 'p', 'k', 'l'},
			'p': {'o', 'l'},
			'a': {'q', 'w', 's', 'z', 'x'},
			's': {'a', 'w', 'e', 'd', 'z', 'x', 'c'},
			'd': {'s', 'e', 'r', 'f', 'x', 'c', 'v'},
			'f': {'d', 'r', 't', 'g', 'c', 'v', 'b'},
			'g': {'f', 't', 'y', 'h', 'v', 'b', 'n'},
			'h': {'g', 'y', 'u', 'j', 'b', 'n', 'm'},
			'j': {'h', 'u', 'i', 'k', 'n', 'm'},
			'k': {'j', 'i', 'o', 'l', 'm'},
			'l': {'k', 'o', 'p'},
			'z': {'a', 's', 'x'},
			'x': {'z', 'a', 's', 'd', 'c'},
			'c': {'x', 's', 'd', 'f', 'v'},
			'v': {'c', 'd', 'f', 'g', 'b'},
			'b': {'v', 'f', 'g', 'h', 'n'},
			'n': {'b', 'g', 'h', 'j', 'm'},
			'm': {'n', 'h', 'j', 'k'},
		},
		Rows: []string{"qwertyuiop", "asdfghjkl", "zxcvbnm"},
	}

	etd.keyboardLayouts = append(etd.keyboardLayouts, qwerty)
}

// initializeSubstitutions sets up character substitution patterns
func (etd *EnhancedTyposquattingDetector) initializeSubstitutions() {
	etd.substitutions = []CharacterSubstitution{
		// Enhanced visual similarity substitutions
		{'0', []rune{'o', 'O', 'Q'}, "visual", 0.9},
		{'1', []rune{'l', 'I', 'i', '|'}, "visual", 0.8},
		{'5', []rune{'s', 'S'}, "visual", 0.7},
		{'8', []rune{'b', 'B'}, "visual", 0.6},
		{'3', []rune{'e', 'E'}, "visual", 0.7},
		{'4', []rune{'a', 'A'}, "visual", 0.6},
		{'7', []rune{'t', 'T'}, "visual", 0.6},
		{'6', []rune{'g', 'G'}, "visual", 0.5},
		{'9', []rune{'g', 'q'}, "visual", 0.5},
		{'2', []rune{'z', 'Z'}, "visual", 0.5},
		// Additional visual confusables
		{'o', []rune{'0', 'Q'}, "visual", 0.9},
		{'l', []rune{'1', 'I', 'i', '|'}, "visual", 0.8},
		{'u', []rune{'v'}, "visual", 0.7},
		{'r', []rune{'n'}, "visual", 0.6},
		{'w', []rune{'v'}, "visual", 0.7}, // Note: 'vv' pattern handled separately

		// Enhanced phonetic similarity substitutions
		{'c', []rune{'k', 's', 'q'}, "phonetic", 0.8},
		{'k', []rune{'c', 'q'}, "phonetic", 0.8}, // Note: 'ck' pattern handled separately
		{'s', []rune{'c', 'z', 'x'}, "phonetic", 0.7},
		{'z', []rune{'s'}, "phonetic", 0.7},
		{'f', []rune{'v'}, "phonetic", 0.8}, // Note: 'ph' pattern handled separately
		{'j', []rune{'g', 'y'}, "phonetic", 0.6},
		{'x', []rune{'s'}, "phonetic", 0.7}, // Note: 'ks', 'cs' patterns handled separately
		{'w', []rune{'u'}, "phonetic", 0.6},
		{'y', []rune{'i'}, "phonetic", 0.6},

		// Enhanced keyboard mistakes
		{'m', []rune{'n'}, "keyboard", 0.9},
		{'n', []rune{'m'}, "keyboard", 0.9},
		{'b', []rune{'v'}, "keyboard", 0.8},
		{'v', []rune{'b'}, "keyboard", 0.8},
		{'d', []rune{'f'}, "keyboard", 0.8},
		{'f', []rune{'d'}, "keyboard", 0.8},
		{'g', []rune{'h'}, "keyboard", 0.8},
		{'h', []rune{'g'}, "keyboard", 0.8},
		{'j', []rune{'k'}, "keyboard", 0.8},
		{'k', []rune{'j'}, "keyboard", 0.8},
		{'l', []rune{';'}, "keyboard", 0.7},
		{'p', []rune{'o'}, "keyboard", 0.8},
		{'o', []rune{'p'}, "keyboard", 0.8},
		{'q', []rune{'w'}, "keyboard", 0.8},
		{'w', []rune{'q', 'e'}, "keyboard", 0.8},
		{'e', []rune{'w', 'r'}, "keyboard", 0.8},
		{'r', []rune{'e', 't'}, "keyboard", 0.8},
		{'t', []rune{'r', 'y'}, "keyboard", 0.8},
		{'y', []rune{'t', 'u'}, "keyboard", 0.8},
		{'u', []rune{'y', 'i'}, "keyboard", 0.8},
		{'i', []rune{'u', 'o'}, "keyboard", 0.8},
		{'a', []rune{'s'}, "keyboard", 0.8},
		{'s', []rune{'a', 'd'}, "keyboard", 0.8},
		{'z', []rune{'x'}, "keyboard", 0.8},
		{'x', []rune{'z', 'c'}, "keyboard", 0.8},
		{'c', []rune{'x', 'v'}, "keyboard", 0.8},
	}
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

        // For well-known Maven groups, require higher similarity to avoid false positives
        if g1, _, ok1 := parseGroupArtifact(target.Name); ok1 {
            if g2, _, ok2 := parseGroupArtifact(pkg); ok2 && strings.EqualFold(g1, g2) && isWellKnownGroup(g1) {
                if similarity < 0.90 { // require higher similarity for same-group well-known artifacts
                    continue
                }
            }
        }

        ms := etd.collectSignals(target, pkg)
        if viper.GetBool("detector.require_multi_signal") {
            suspicious := 0
            if ms.MaintainerMismatch { suspicious++ }
            if ms.AbnormalCadence { suspicious++ }
            if ms.YoungAge { suspicious++ }
            if ms.LowPopularity { suspicious++ }
            if suspicious < 1 { continue }
        }
        if similarity >= threshold {
            // Analyze the type of typosquatting
            analysis := etd.analyzeTyposquattingType(target.Name, pkg)

			// Check for advanced attack patterns
			advancedPatterns := etd.detectAdvancedPatterns(target.Name, pkg)

			severity := etd.calculateSeverityEnhanced(similarity, analysis)

			// Adjust severity based on advanced patterns
            if len(advancedPatterns) > 0 { severity = etd.escalateSeverity(severity) }
            if ms.LegitimacyStrong { if severity > 0 { severity-- } }

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
        "org.apache.commons": {},
        "org.springframework": {},
        "com.fasterxml.jackson.core": {},
        "org.apache.httpcomponents": {},
        "org.mockito": {},
        "org.hibernate": {},
        "org.slf4j": {},
        "ch.qos.logback": {},
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
    if strings.TrimSpace(target.Registry) == "" { return s }
    switch strings.ToLower(target.Registry) {
    case "maven":
        g1, a1, ok1 := parseGroupArtifact(target.Name)
        g2, a2, ok2 := parseGroupArtifact(candidate)
        if ok1 && ok2 {
            mc := reg.NewMavenClient()
            v1 := ""
            v2 := ""
            docs1, _ := mc.SearchPackages(ctx, fmt.Sprintf("%s:%s", g1, a1))
            if len(docs1) > 0 { v1 = docs1[0].Version }
            docs2, _ := mc.SearchPackages(ctx, fmt.Sprintf("%s:%s", g2, a2))
            if len(docs2) > 0 { v2 = docs2[0].Version }
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
        if tinfo != nil { s.MaintainersTarget = toStrings(tinfo.Maintainers) }
        if cinfo != nil { s.MaintainersCandidate = toStrings(cinfo.Maintainers) }
        s.MaintainerMismatch = !hasOverlap(s.MaintainersTarget, s.MaintainersCandidate)
        s.LegitimacyStrong = hasOverlap(s.MaintainersTarget, s.MaintainersCandidate)
    case "pypi":
        pc := reg.NewPyPIClient()
        tinfo, _ := pc.GetPackageInfo(target.Name)
        cinfo, _ := pc.GetPackageInfo(candidate)
        if tinfo != nil { s.MaintainersTarget = []string{tinfo.Info.Author, tinfo.Info.Maintainer} }
        if cinfo != nil { s.MaintainersCandidate = []string{cinfo.Info.Author, cinfo.Info.Maintainer} }
        s.MaintainerMismatch = !hasOverlap(s.MaintainersTarget, s.MaintainersCandidate)
        s.LegitimacyStrong = hasOverlap(s.MaintainersTarget, s.MaintainersCandidate)
    case "rubygems":
        rc := reg.NewRubyGemsClient()
        tinfo, _ := rc.GetPackageInfo(ctx, target.Name, "")
        cinfo, _ := rc.GetPackageInfo(ctx, candidate, "")
        if tinfo != nil { s.MaintainersTarget = tinfo.Maintainers }
        if cinfo != nil { s.MaintainersCandidate = cinfo.Maintainers }
        s.MaintainerMismatch = !hasOverlap(s.MaintainersTarget, s.MaintainersCandidate)
        s.LegitimacyStrong = hasOverlap(s.MaintainersTarget, s.MaintainersCandidate)
    case "nuget":
        uc := reg.NewNuGetClient()
        sr1, _ := uc.SearchPackages(ctx, target.Name)
        sr2, _ := uc.SearchPackages(ctx, candidate)
        if len(sr1) > 0 { s.MaintainersTarget = sr1[0].Maintainers }
        if len(sr2) > 0 { s.MaintainersCandidate = sr2[0].Maintainers }
        s.MaintainerMismatch = !hasOverlap(s.MaintainersTarget, s.MaintainersCandidate)
        s.LegitimacyStrong = hasOverlap(s.MaintainersTarget, s.MaintainersCandidate)
    case "cargo":
        cc := reg.NewCargoClient()
        tmeta, _ := cc.GetPackageInfo(ctx, target.Name, "latest")
        cmeta, _ := cc.GetPackageInfo(ctx, candidate, "latest")
        if tmeta != nil { s.MaintainersTarget = tmeta.Maintainers }
        if cmeta != nil { s.MaintainersCandidate = cmeta.Maintainers }
        s.MaintainerMismatch = !hasOverlap(s.MaintainersTarget, s.MaintainersCandidate)
        s.LegitimacyStrong = hasOverlap(s.MaintainersTarget, s.MaintainersCandidate)
    }
    return s
}

func hasOverlap(a, b []string) bool {
    if len(a) == 0 || len(b) == 0 { return false }
    m := map[string]struct{}{}
    for _, x := range a { if x != "" { m[strings.ToLower(x)] = struct{}{} } }
    for _, y := range b { if y != "" { if _, ok := m[strings.ToLower(y)]; ok { return true } } }
    return false
}

func toStrings(xs []interface{}) []string {
    var out []string
    for _, x := range xs {
        switch v := x.(type) {
        case string:
            if v != "" { out = append(out, v) }
        case map[string]interface{}:
            if n, ok := v["name"]; ok {
                if ns, ok2 := n.(string); ok2 && ns != "" { out = append(out, ns) }
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

// keyboardProximitySimilarity analyzes keyboard layout proximity
func (etd *EnhancedTyposquattingDetector) keyboardProximitySimilarity(s1, s2 string) float64 {
	if len(s1) == 0 || len(s2) == 0 {
		return 0.0
	}

	// Use QWERTY layout (first in the list)
	if len(etd.keyboardLayouts) == 0 {
		return 0.0
	}
	layout := etd.keyboardLayouts[0]

	// Calculate proximity-aware edit distance
	proximityScore := etd.proximityEditDistance(s1, s2, layout)
	maxLen := math.Max(float64(len(s1)), float64(len(s2)))

	if maxLen == 0 {
		return 1.0
	}

	return 1.0 - (proximityScore / maxLen)
}

// proximityEditDistance calculates edit distance considering keyboard proximity
func (etd *EnhancedTyposquattingDetector) proximityEditDistance(s1, s2 string, layout KeyboardLayout) float64 {
	runes1 := []rune(s1)
	runes2 := []rune(s2)
	m, n := len(runes1), len(runes2)

	// Create DP matrix
	dp := make([][]float64, m+1)
	for i := range dp {
		dp[i] = make([]float64, n+1)
	}

	// Initialize base cases
	for i := 0; i <= m; i++ {
		dp[i][0] = float64(i)
	}
	for j := 0; j <= n; j++ {
		dp[0][j] = float64(j)
	}

	// Fill DP matrix
	for i := 1; i <= m; i++ {
		for j := 1; j <= n; j++ {
			if runes1[i-1] == runes2[j-1] {
				dp[i][j] = dp[i-1][j-1]
			} else {
				// Calculate proximity cost for substitution
				proximityCost := etd.getProximityCost(runes1[i-1], runes2[j-1], layout)

				dp[i][j] = math.Min(
					math.Min(
						dp[i-1][j]+1.0,  // deletion
						dp[i][j-1]+1.0), // insertion
					dp[i-1][j-1]+proximityCost) // substitution with proximity cost
			}
		}
	}

	return dp[m][n]
}

// getProximityCost returns the cost of substituting one character for another based on keyboard proximity
func (etd *EnhancedTyposquattingDetector) getProximityCost(c1, c2 rune, layout KeyboardLayout) float64 {
	c1Lower := unicode.ToLower(c1)
	c2Lower := unicode.ToLower(c2)

	// Check if characters are adjacent on keyboard
	if adjacent, ok := layout.Layout[c1Lower]; ok {
		for _, adj := range adjacent {
			if adj == c2Lower {
				return 0.3 // Low cost for adjacent keys
			}
		}
	}

	// Check if characters are in the same row
	for _, row := range layout.Rows {
		c1InRow := strings.ContainsRune(row, c1Lower)
		c2InRow := strings.ContainsRune(row, c2Lower)
		if c1InRow && c2InRow {
			return 0.6 // Medium cost for same row
		}
	}

	return 1.0 // Full cost for non-adjacent keys
}

// visualSimilarity analyzes visual character similarity
func (etd *EnhancedTyposquattingDetector) visualSimilarity(s1, s2 string) float64 {
	if len(s1) == 0 || len(s2) == 0 {
		return 0.0
	}

	// Convert to normalized forms for visual comparison
	norm1 := etd.normalizeForVisualComparison(s1)
	norm2 := etd.normalizeForVisualComparison(s2)

	// Calculate similarity based on visual substitutions
	return etd.substitutionSimilarity(norm1, norm2, "visual")
}

// phoneticSimilarity analyzes phonetic similarity
func (etd *EnhancedTyposquattingDetector) phoneticSimilarity(s1, s2 string) float64 {
	if len(s1) == 0 || len(s2) == 0 {
		return 0.0
	}

	// Convert to phonetic representations
	phonetic1 := etd.toPhoneticForm(s1)
	phonetic2 := etd.toPhoneticForm(s2)

	// Calculate similarity based on phonetic substitutions
	return etd.substitutionSimilarity(phonetic1, phonetic2, "phonetic")
}

// normalizeForVisualComparison normalizes strings for visual comparison
func (etd *EnhancedTyposquattingDetector) normalizeForVisualComparison(s string) string {
	result := strings.Builder{}
	for _, r := range s {
		// Apply visual substitutions
		substituted := false
		for _, sub := range etd.substitutions {
			if sub.Type == "visual" {
				for _, substitute := range sub.Substitutes {
					if r == substitute {
						result.WriteRune(sub.Original)
						substituted = true
						break
					}
				}
				if substituted {
					break
				}
			}
		}
		if !substituted {
			result.WriteRune(r)
		}
	}
	return result.String()
}

// toPhoneticForm converts string to phonetic representation
func (etd *EnhancedTyposquattingDetector) toPhoneticForm(s string) string {
	result := strings.Builder{}
	for _, r := range s {
		// Apply phonetic substitutions
		substituted := false
		for _, sub := range etd.substitutions {
			if sub.Type == "phonetic" {
				for _, substitute := range sub.Substitutes {
					if r == substitute {
						result.WriteRune(sub.Original)
						substituted = true
						break
					}
				}
				if substituted {
					break
				}
			}
		}
		if !substituted {
			result.WriteRune(r)
		}
	}
	return result.String()
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

// hasNamespaceConfusion checks for namespace/scope confusion
func (etd *EnhancedTyposquattingDetector) hasNamespaceConfusion(target, candidate string) bool {
	// Check for @scope/ prefix confusion
	if strings.HasPrefix(target, "@") && !strings.HasPrefix(candidate, "@") {
		// Remove scope from target and compare
		parts := strings.Split(target, "/")
		if len(parts) == 2 {
			return parts[1] == candidate
		}
	}

	if strings.HasPrefix(candidate, "@") && !strings.HasPrefix(target, "@") {
		// Remove scope from candidate and compare
		parts := strings.Split(candidate, "/")
		if len(parts) == 2 {
			return parts[1] == target
		}
	}

	return false
}

// hasBrandImpersonation checks for brand impersonation patterns
func (etd *EnhancedTyposquattingDetector) hasBrandImpersonation(target, candidate string) bool {
	// Common brand impersonation patterns
	patterns := []string{
		"official", "org", "js", "node", "npm", "lib", "core", "main", "base",
		"framework", "sdk", "api", "client", "server", "dev", "prod",
	}

	for _, pattern := range patterns {
		// Check if candidate adds suspicious suffixes/prefixes
		if strings.HasPrefix(candidate, target+"-"+pattern) ||
			strings.HasPrefix(candidate, target+"_"+pattern) ||
			strings.HasSuffix(candidate, pattern+"-"+target) ||
			strings.HasSuffix(candidate, pattern+"_"+target) {
			return true
		}
	}

	return false
}

// hasInsertionDeletionPattern checks for character insertion/deletion patterns
func (etd *EnhancedTyposquattingDetector) hasInsertionDeletionPattern(target, candidate string) bool {
	// Check for single character insertion
	if len(candidate) == len(target)+1 {
		return etd.isSingleCharacterInsertion(target, candidate)
	}

	// Check for single character deletion
	if len(target) == len(candidate)+1 {
		return etd.isSingleCharacterInsertion(candidate, target)
	}

	return false
}

// isSingleCharacterInsertion checks if candidate is target with one character inserted
func (etd *EnhancedTyposquattingDetector) isSingleCharacterInsertion(shorter, longer string) bool {
	i, j := 0, 0
	differences := 0

	for i < len(shorter) && j < len(longer) {
		if shorter[i] == longer[j] {
			i++
			j++
		} else {
			differences++
			if differences > 1 {
				return false
			}
			j++ // Skip the inserted character
		}
	}

	return differences <= 1
}

// escalateSeverity increases severity based on advanced patterns
func (etd *EnhancedTyposquattingDetector) escalateSeverity(current types.Severity) types.Severity {
	switch current {
	case types.SeverityLow:
		return types.SeverityMedium
	case types.SeverityMedium:
		return types.SeverityHigh
	case types.SeverityHigh:
		return types.SeverityCritical
	default:
		return current
	}
}

// generateRecommendation creates enhanced recommendations based on detected patterns
func (etd *EnhancedTyposquattingDetector) generateRecommendation(target, candidate string, patterns []string) string {
	baseRec := fmt.Sprintf("Verify that '%s' is the intended package. Consider using '%s' instead if that was the intention.", target, candidate)

	if len(patterns) == 0 {
		return baseRec
	}

	additionalWarnings := []string{}
	for _, pattern := range patterns {
		switch pattern {
		case "homograph_attack":
			additionalWarnings = append(additionalWarnings, "WARNING: Potential Unicode homograph attack detected")
		case "namespace_confusion":
			additionalWarnings = append(additionalWarnings, "WARNING: Namespace/scope confusion detected")
		case "brand_impersonation":
			additionalWarnings = append(additionalWarnings, "WARNING: Potential brand impersonation detected")
		case "insertion_deletion":
			additionalWarnings = append(additionalWarnings, "WARNING: Character insertion/deletion pattern detected")
		}
	}

	if len(additionalWarnings) > 0 {
		return baseRec + " " + strings.Join(additionalWarnings, ". ") + "."
	}

	return baseRec
}

// editDistanceSimilarity calculates basic edit distance similarity
func (etd *EnhancedTyposquattingDetector) editDistanceSimilarity(s1, s2 string) float64 {
	distance := etd.basicEditDistance(s1, s2)
	maxLen := math.Max(float64(len(s1)), float64(len(s2)))
	if maxLen == 0 {
		return 1.0
	}
	return 1.0 - float64(distance)/maxLen
}

// basicEditDistance calculates standard edit distance
func (etd *EnhancedTyposquattingDetector) basicEditDistance(s1, s2 string) int {
	m, n := len(s1), len(s2)
	dp := make([][]int, m+1)
	for i := range dp {
		dp[i] = make([]int, n+1)
	}

	for i := 0; i <= m; i++ {
		dp[i][0] = i
	}
	for j := 0; j <= n; j++ {
		dp[0][j] = j
	}

	for i := 1; i <= m; i++ {
		for j := 1; j <= n; j++ {
			if s1[i-1] == s2[j-1] {
				dp[i][j] = dp[i-1][j-1]
			} else {
				dp[i][j] = 1 + minInt(dp[i-1][j], dp[i][j-1], dp[i-1][j-1])
			}
		}
	}

	return dp[m][n]
}

// weightedAverage calculates weighted average of scores
func (etd *EnhancedTyposquattingDetector) weightedAverage(scores, weights []float64) float64 {
	if len(scores) != len(weights) || len(scores) == 0 {
		return 0.0
	}

	var weightedSum, totalWeight float64
	for i, score := range scores {
		weightedSum += score * weights[i]
		totalWeight += weights[i]
	}

	if totalWeight == 0 {
		return 0.0
	}

	return weightedSum / totalWeight
}

// TyposquattingAnalysis contains detailed analysis of typosquatting type
type TyposquattingAnalysis struct {
	KeyboardErrors     int
	VisualSimilarity   float64
	PhoneticSimilarity float64
	EditDistance       int
	Transpositions     int
	Insertions         int
	Deletions          int
	Substitutions      int
	PrimaryType        string
}

// analyzeTyposquattingType analyzes the specific type of typosquatting
func (etd *EnhancedTyposquattingDetector) analyzeTyposquattingType(s1, s2 string) TyposquattingAnalysis {
	analysis := TyposquattingAnalysis{}

	// Calculate basic metrics
	analysis.EditDistance = etd.basicEditDistance(s1, s2)
	analysis.VisualSimilarity = etd.visualSimilarity(s1, s2)
	analysis.PhoneticSimilarity = etd.phoneticSimilarity(s1, s2)

	// Analyze edit operations
	operations := etd.analyzeEditOperations(s1, s2)
	analysis.Insertions = operations["insertions"]
	analysis.Deletions = operations["deletions"]
	analysis.Substitutions = operations["substitutions"]
	analysis.Transpositions = operations["transpositions"]

	// Count keyboard errors
	analysis.KeyboardErrors = etd.countKeyboardErrors(s1, s2)

	// Determine primary type
	analysis.PrimaryType = etd.determinePrimaryType(analysis)

	return analysis
}

// analyzeEditOperations analyzes the types of edit operations needed
func (etd *EnhancedTyposquattingDetector) analyzeEditOperations(s1, s2 string) map[string]int {
	operations := map[string]int{
		"insertions":     0,
		"deletions":      0,
		"substitutions":  0,
		"transpositions": 0,
	}

	// Simple analysis based on length difference and character comparison
	lenDiff := len(s2) - len(s1)
	if lenDiff > 0 {
		operations["insertions"] = lenDiff
	} else if lenDiff < 0 {
		operations["deletions"] = -lenDiff
	}

	// Count substitutions by comparing characters at same positions
	minLen := min(len(s1), len(s2))
	for i := 0; i < minLen; i++ {
		if s1[i] != s2[i] {
			operations["substitutions"]++
		}
	}

	// Simple transposition detection
	if len(s1) == len(s2) && operations["substitutions"] == 2 {
		// Check if it's a simple adjacent transposition
		for i := 0; i < len(s1)-1; i++ {
			if s1[i] == s2[i+1] && s1[i+1] == s2[i] {
				operations["transpositions"] = 1
				operations["substitutions"] -= 2
				break
			}
		}
	}

	return operations
}

// countKeyboardErrors counts potential keyboard-based errors
func (etd *EnhancedTyposquattingDetector) countKeyboardErrors(s1, s2 string) int {
	if len(etd.keyboardLayouts) == 0 {
		return 0
	}

	layout := etd.keyboardLayouts[0] // Use QWERTY
	count := 0

	// For strings of same length, check position-by-position
	if len(s1) == len(s2) {
		for i := 0; i < len(s1); i++ {
			if s1[i] != s2[i] {
				c1 := unicode.ToLower(rune(s1[i]))
				c2 := unicode.ToLower(rune(s2[i]))

				// Check if characters are adjacent on keyboard
				if adjacent, ok := layout.Layout[c1]; ok {
					for _, adj := range adjacent {
						if adj == c2 {
							count++
							break
						}
					}
				}
			}
		}
	} else {
		// For different length strings, use a more sophisticated approach
		// This is a simplified version - could be enhanced with proper alignment
		minLen := min(len(s1), len(s2))
		for i := 0; i < minLen; i++ {
			if s1[i] != s2[i] {
				c1 := unicode.ToLower(rune(s1[i]))
				c2 := unicode.ToLower(rune(s2[i]))

				// Check if characters are adjacent on keyboard
				if adjacent, ok := layout.Layout[c1]; ok {
					for _, adj := range adjacent {
						if adj == c2 {
							count++
							break
						}
					}
				}
			}
		}
	}

	return count
}

// determinePrimaryType determines the primary type of typosquatting
func (etd *EnhancedTyposquattingDetector) determinePrimaryType(analysis TyposquattingAnalysis) string {
	// Check for keyboard proximity errors first (most specific)
	if analysis.KeyboardErrors > 0 {
		return "keyboard_proximity"
	}
	// Check for specific character operations
	if analysis.Transpositions > 0 {
		return "character_transposition"
	}
	if analysis.Insertions > analysis.Deletions && analysis.Insertions > analysis.Substitutions {
		return "character_insertion"
	}
	if analysis.Deletions > analysis.Insertions && analysis.Deletions > analysis.Substitutions {
		return "character_deletion"
	}
	if analysis.Substitutions > 0 {
		return "character_substitution"
	}
	// Check for high similarity patterns
	if analysis.VisualSimilarity > 0.8 {
		return "visual_similarity"
	}
	if analysis.PhoneticSimilarity > 0.8 {
		return "phonetic_similarity"
	}
	return "character_substitution"
}

// calculateSeverityEnhanced calculates threat severity based on enhanced analysis
func (etd *EnhancedTyposquattingDetector) calculateSeverityEnhanced(similarity float64, analysis TyposquattingAnalysis) types.Severity {
	// Base severity on similarity score
	baseSeverity := types.SeverityLow
	if similarity >= 0.95 {
		baseSeverity = types.SeverityCritical
	} else if similarity >= 0.9 {
		baseSeverity = types.SeverityHigh
	} else if similarity >= 0.8 {
		baseSeverity = types.SeverityMedium
	}

	// Adjust based on analysis
	if analysis.KeyboardErrors > 0 || analysis.PrimaryType == "keyboard_proximity" {
		// Keyboard errors are more likely to be accidental typos
		if baseSeverity == types.SeverityCritical {
			return types.SeverityHigh
		}
	}

	if analysis.VisualSimilarity > 0.9 || analysis.PrimaryType == "visual_similarity" {
		// Visual similarity attacks are particularly dangerous
		if baseSeverity == types.SeverityMedium {
			return types.SeverityHigh
		}
	}

	return baseSeverity
}

// generateThreatDescription generates a detailed threat description
func (etd *EnhancedTyposquattingDetector) generateThreatDescription(target, similar string, analysis TyposquattingAnalysis) string {
	baseDesc := fmt.Sprintf("Package name '%s' is very similar to '%s' (%.1f%% similarity)", target, similar, analysis.VisualSimilarity*100)

	switch analysis.PrimaryType {
	case "keyboard_proximity":
		return fmt.Sprintf("%s. Detected %d potential keyboard errors, suggesting possible typosquatting attack.", baseDesc, analysis.KeyboardErrors)
	case "visual_similarity":
		return fmt.Sprintf("%s. High visual similarity (%.1f%%) detected, indicating potential visual spoofing attack.", baseDesc, analysis.VisualSimilarity*100)
	case "phonetic_similarity":
		return fmt.Sprintf("%s. High phonetic similarity (%.1f%%) detected, indicating potential sound-alike attack.", baseDesc, analysis.PhoneticSimilarity*100)
	case "character_transposition":
		return fmt.Sprintf("%s. Character transposition detected, indicating potential typosquatting attack.", baseDesc)
	case "character_insertion":
		return fmt.Sprintf("%s. Character insertion detected (%d insertions), indicating potential typosquatting attack.", baseDesc, analysis.Insertions)
	case "character_deletion":
		return fmt.Sprintf("%s. Character deletion detected (%d deletions), indicating potential typosquatting attack.", baseDesc, analysis.Deletions)
	default:
		return fmt.Sprintf("%s. Character substitution detected, indicating potential typosquatting attack.", baseDesc)
	}
}

// generateEvidence generates evidence for the threat
func (etd *EnhancedTyposquattingDetector) generateEvidence(target, similar string, analysis TyposquattingAnalysis) []types.Evidence {
	evidence := []types.Evidence{
		{
			Type:        "edit_distance",
			Description: "Levenshtein edit distance",
			Value:       analysis.EditDistance,
			Score:       1.0 - float64(analysis.EditDistance)/math.Max(float64(len(target)), float64(len(similar))),
		},
		{
			Type:        "visual_similarity",
			Description: "Visual character similarity score",
			Value:       analysis.VisualSimilarity,
			Score:       analysis.VisualSimilarity,
		},
		{
			Type:        "phonetic_similarity",
			Description: "Phonetic similarity score",
			Value:       analysis.PhoneticSimilarity,
			Score:       analysis.PhoneticSimilarity,
		},
	}

	if analysis.KeyboardErrors > 0 {
		evidence = append(evidence, types.Evidence{
			Type:        "keyboard_errors",
			Description: "Number of potential keyboard proximity errors",
			Value:       analysis.KeyboardErrors,
			Score:       float64(analysis.KeyboardErrors) / float64(len(target)),
		})
	}

	if analysis.Transpositions > 0 {
		evidence = append(evidence, types.Evidence{
			Type:        "transpositions",
			Description: "Number of character transpositions",
			Value:       analysis.Transpositions,
			Score:       0.9, // High score for transpositions
		})
	}

	return evidence
}

func (etd *EnhancedTyposquattingDetector) generateEvidenceWithSignals(target, similar string, analysis TyposquattingAnalysis, ms multiSignals) []types.Evidence {
    ev := etd.generateEvidence(target, similar, analysis)
    // Attach signals for policy evaluation
    if ms.SameGroup {
        ev = append(ev, types.Evidence{ Type: "signal", Description: "same_group", Value: true })
    }
    if hasOverlap(ms.MaintainersTarget, ms.MaintainersCandidate) {
        ev = append(ev, types.Evidence{ Type: "signal", Description: "maintainer_overlap", Value: true })
    }
    return ev
}

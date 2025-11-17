// RUNT - Release-Unusual Name Tokenizer
// Advanced typosquatting detection using multiple string similarity metrics
// and Bayesian mixture models
package edge

import (
    "context"
    "fmt"
    "math"
    "sort"
    "strings"
    "time"
    "unicode"
    "sync"
    "sync/atomic"
    "github.com/Alivanroy/Typosentinel/internal/registry"
)

// RUNTAlgorithm implements the RUNT algorithm for typosquatting detection
type RUNTAlgorithm struct {
    config  *RUNTConfig
    metrics *AlgorithmMetrics

    // Pre-computed similarity matrices
    visualSimilarityMap map[rune][]rune
    visualReverseMap    map[rune]rune
    phoneticEncoder     *PhoneticEncoder
    semanticModel       *SemanticModel

	// Bayesian mixture model
	mixtureModel *BayesianMixtureModel

    // Known package database
    knownPackages map[string]bool

    // Registry connector
    npmConnector *registry.NPMConnector

    // Dependency cache
    depCache   map[string][]string
    depCacheTS map[string]time.Time
    depMu      sync.RWMutex
    depCacheHits   int64
    depCacheMisses int64
}

// RUNTConfig contains configuration for the RUNT algorithm
type RUNTConfig struct {
    // Similarity thresholds
    LevenshteinThreshold float64 `json:"levenshtein_threshold"`
    JaroWinklerThreshold float64 `json:"jaro_winkler_threshold"`
    PhoneticThreshold    float64 `json:"phonetic_threshold"`
    VisualThreshold      float64 `json:"visual_threshold"`
    SemanticThreshold    float64 `json:"semantic_threshold"`

    // Bayesian model parameters
    MixtureComponents int     `json:"mixture_components"`
    PriorWeight       float64 `json:"prior_weight"`

    // Detection parameters
    OverallThreshold      float64 `json:"overall_threshold"`
    MinPackageLength      int     `json:"min_package_length"`
    MaxPackageLength      int     `json:"max_package_length"`
    EnableUnicodeAnalysis bool    `json:"enable_unicode_analysis"`
    MaxDependencyDepth    int     `json:"max_dependency_depth"`
    EnableDependencyAnalysis bool `json:"enable_dependency_analysis"`
    DependencyCacheTTLMinutes int `json:"dependency_cache_ttl_minutes"`
    UnicodeAttackThreshold   float64 `json:"unicode_attack_threshold"`
    KeyboardAttackThreshold  float64 `json:"keyboard_attack_threshold"`
    VisualAttackThreshold    float64 `json:"visual_attack_threshold"`
    PhoneticAttackThreshold  float64 `json:"phonetic_attack_threshold"`
}

// PhoneticEncoder handles phonetic encoding for sound-alike detection
type PhoneticEncoder struct {
	soundexMap map[rune]rune
}

// SemanticModel handles semantic similarity using word embeddings
type SemanticModel struct {
	embeddings map[string][]float64
	vocabulary map[string]bool
}

// BayesianMixtureModel implements Bayesian mixture modeling
type BayesianMixtureModel struct {
	components []MixtureComponent
	weights    []float64
	trained    bool
}

// MixtureComponent represents a single component in the mixture model
type MixtureComponent struct {
	mean       []float64
	covariance [][]float64
	weight     float64
}

// SimilarityFeatures contains all computed similarity features
type SimilarityFeatures struct {
	Levenshtein    float64 `json:"levenshtein"`
	JaroWinkler    float64 `json:"jaro_winkler"`
	Phonetic       float64 `json:"phonetic"`
	Visual         float64 `json:"visual"`
	Semantic       float64 `json:"semantic"`
	LCS            float64 `json:"lcs"` // Longest Common Subsequence
	Hamming        float64 `json:"hamming"`
	Cosine         float64 `json:"cosine"`
	Jaccard        float64 `json:"jaccard"`
	NGram          float64 `json:"ngram"`
	KeyboardLayout float64 `json:"keyboard_layout"`
	Unicode        float64 `json:"unicode"`
}

// NewRUNTAlgorithm creates a new RUNT algorithm instance
func NewRUNTAlgorithm(config *RUNTConfig) *RUNTAlgorithm {
    if config == nil {
        config = &RUNTConfig{
            LevenshteinThreshold:  0.8,
            JaroWinklerThreshold:  0.85,
            PhoneticThreshold:     0.9,
            VisualThreshold:       0.85,
            SemanticThreshold:     0.8,
            MixtureComponents:     5,
            PriorWeight:           0.1,
            OverallThreshold:      0.75,
            MinPackageLength:      2,
            MaxPackageLength:      100,
            EnableUnicodeAnalysis: true,
            MaxDependencyDepth:    2,
            EnableDependencyAnalysis: true,
            DependencyCacheTTLMinutes: 10,
            UnicodeAttackThreshold:   0.7,
            KeyboardAttackThreshold:  0.7,
            VisualAttackThreshold:    0.8,
            PhoneticAttackThreshold:  0.8,
        }
    }

    runt := &RUNTAlgorithm{
        config: config,
        metrics: &AlgorithmMetrics{
            LastUpdated: time.Now(),
        },
        knownPackages: make(map[string]bool),
        depCache:      make(map[string][]string),
        depCacheTS:    make(map[string]time.Time),
    }

	runt.initializeComponents()
	return runt
}

// Algorithm interface implementation

func (r *RUNTAlgorithm) Name() string {
	return "RUNT"
}

func (r *RUNTAlgorithm) Tier() AlgorithmTier {
	return TierCore
}

func (r *RUNTAlgorithm) Description() string {
	return "Release-Unusual Name Tokenizer: Advanced typosquatting detection using multiple similarity metrics and Bayesian mixture models"
}

func (r *RUNTAlgorithm) Configure(config map[string]interface{}) error {
    // Update configuration from map
    if threshold, ok := config["overall_threshold"].(float64); ok {
        r.config.OverallThreshold = threshold
    }
    if v, ok := config["unicode_attack_threshold"].(float64); ok {
        r.config.UnicodeAttackThreshold = v
    }
    if v, ok := config["keyboard_attack_threshold"].(float64); ok {
        r.config.KeyboardAttackThreshold = v
    }
    if v, ok := config["visual_attack_threshold"].(float64); ok {
        r.config.VisualAttackThreshold = v
    }
    if v, ok := config["phonetic_attack_threshold"].(float64); ok {
        r.config.PhoneticAttackThreshold = v
    }
    return nil
}

func (r *RUNTAlgorithm) GetMetrics() *AlgorithmMetrics {
	return r.metrics
}

func (r *RUNTAlgorithm) Analyze(ctx context.Context, packages []string) (*AlgorithmResult, error) {
	startTime := time.Now()

	result := &AlgorithmResult{
		Algorithm: r.Name(),
		Timestamp: startTime,
		Packages:  packages,
		Findings:  make([]Finding, 0),
		Metadata:  make(map[string]interface{}),
	}

	// Analyze each package
    analyzedGlobal := make(map[string]bool)
    simCache := make(map[string][]SuspiciousPackage)
    for _, packageName := range packages {
		// Validate package name length
		if len(packageName) < r.config.MinPackageLength || len(packageName) > r.config.MaxPackageLength {
			continue
		}

		// Find similar packages and compute threat score
		suspiciousPackages := r.findSuspiciousPackages(packageName)

        if len(suspiciousPackages) > 0 {
            // Add findings for each suspicious package
            for _, suspicious := range suspiciousPackages {
                if suspicious.SimilarityScore > r.config.OverallThreshold {
                    evidences := []Evidence{
                        {
                            Type:        "target_package",
                            Description: "Target package for typosquatting",
                            Value:       suspicious.Name,
                            Score:       suspicious.SimilarityScore,
                        },
                        {
                            Type:        "similarity_features",
                            Description: "Similarity analysis features",
                            Value:       suspicious.Features,
                            Score:       suspicious.SimilarityScore,
                        },
                        {
                            Type:        "attack_type",
                            Description: "Type of typosquatting attack",
                            Value:       suspicious.AttackType,
                            Score:       0.8,
                        },
                    }
                    if suspicious.Features.KeyboardLayout > 0.7 {
                        evidences = append(evidences, Evidence{
                            Type:        "keyboard_detail",
                            Description: "Adjacent key matches and transpositions",
                            Value:       r.keyboardAdjacencyDetails(packageName, suspicious.Name),
                            Score:       suspicious.Features.KeyboardLayout,
                        })
                    }
                    if suspicious.Features.Unicode > 0.7 {
                        evidences = append(evidences, Evidence{
                            Type:        "unicode_detail",
                            Description: "Unicode script and visual normalization analysis",
                            Value:       r.unicodeDetails(packageName, suspicious.Name),
                            Score:       suspicious.Features.Unicode,
                        })
                    }
                    if suspicious.Features.Semantic > 0.7 {
                        evidences = append(evidences, Evidence{
                            Type:        "semantic_detail",
                            Description: "Token matching and stripped-name similarity",
                            Value:       r.semanticDetails(packageName, suspicious.Name),
                            Score:       suspicious.Features.Semantic,
                        })
                    }

                    // Attach attack threshold used based on selected attack type
                    thr := 0.0
                    switch suspicious.AttackType {
                    case "UNICODE_CONFUSION":
                        thr = r.config.UnicodeAttackThreshold
                    case "KEYBOARD_TYPO":
                        thr = r.config.KeyboardAttackThreshold
                    case "HOMOGLYPH_ATTACK":
                        thr = r.config.VisualAttackThreshold
                    case "PHONETIC_SQUATTING":
                        thr = r.config.PhoneticAttackThreshold
                    }
                    if thr > 0 {
                        evidences = append(evidences, Evidence{
                            Type:        "attack_threshold_used",
                            Description: "Threshold applied for selected attack classification",
                            Value:       thr,
                            Score:       suspicious.SimilarityScore,
                        })
                    }
                    dn, dv := r.dominantFeature(suspicious.Features)
                    finding := Finding{
                        ID:              fmt.Sprintf("runt_typosquatting_%s", packageName),
                        Package:         packageName,
                        Type:            "TYPOSQUATTING_DETECTED",
                        Severity:        r.getSeverity(r.computeConfidence(suspicious.Features)),
                        Message:         fmt.Sprintf("%s: '%s' ~ '%s' (confidence=%.2f)", suspicious.AttackType, packageName, suspicious.Name, r.computeConfidence(suspicious.Features)),
                        Confidence:      r.computeConfidence(suspicious.Features),
                        DetectedAt:      time.Now().UTC(),
                        DetectionMethod: "runt_similarity_analysis",
                        Evidence:        append(evidences, Evidence{
                            Type:        "feature_contributions",
                            Description: "Weighted contributions to overall similarity",
                            Value:       r.featureContributions(suspicious.Features),
                            Score:       suspicious.SimilarityScore,
                        }, Evidence{
                            Type:        "dominant_feature",
                            Description: "Highest raw feature contributing to detection",
                            Value:       map[string]interface{}{"name": dn, "value": dv},
                            Score:       dv,
                        }, Evidence{
                            Type:        "similarity_summary",
                            Description: "Top feature contributions",
                            Value:       r.topContributions(r.featureContributions(suspicious.Features), 3),
                            Score:       suspicious.SimilarityScore,
                        }),
                    }
                    result.Findings = append(result.Findings, finding)
                }
            }

            // Add metadata
            result.Metadata[fmt.Sprintf("%s_suspicious_packages_count", packageName)] = len(suspiciousPackages)
            result.Metadata[fmt.Sprintf("%s_max_similarity_score", packageName)] = suspiciousPackages[0].SimilarityScore
            // Registry-derived features
            deps := r.getDependencies(ctx, packageName)
            if len(deps) > 0 {
                sample := deps
                if len(sample) > 10 {
                    sample = sample[:10]
                }
                result.Metadata[fmt.Sprintf("%s_deps_count", packageName)] = len(deps)
                result.Metadata[fmt.Sprintf("%s_deps_sample", packageName)] = sample
            }
        }

        if r.config.EnableDependencyAnalysis {
            rf := r.recursiveAnalyzeDependencies(ctx, packageName, 0, r.config.MaxDependencyDepth, make(map[string]bool), analyzedGlobal, simCache)
            if len(rf) > 0 {
                result.Findings = append(result.Findings, rf...)
            }
        }
    }
    if len(result.Findings) > 0 {
        summary := r.computeAttackSummary(result.Findings)
        result.Metadata["attack_summary"] = summary
        result.Metadata["evidence_summary"] = r.computeEvidenceSummary(result.Findings)
        maxScore := 0.0
        sumScore := 0.0
        var top Finding
        for _, f := range result.Findings {
            sumScore += f.Confidence
            if f.Confidence > maxScore {
                maxScore = f.Confidence
                top = f
            }
        }
        avg := 0.0
        if len(result.Findings) > 0 {
            avg = sumScore / float64(len(result.Findings))
        }
        result.Metadata["runt_overall_score"] = maxScore
        result.Metadata["runt_average_score"] = avg
        result.Metadata["runt_risk_level"] = r.getSeverity(maxScore)
        // Extract attack type from top finding evidence if available
        if len(top.Evidence) > 0 {
            for _, e := range top.Evidence {
                if e.Type == "attack_type" {
                    if at, ok := e.Value.(string); ok {
                        result.Metadata["runt_top_attack_type"] = at
                    }
                    break
                }
            }
        }
        // Extract dominant feature from top finding evidence if available
        if len(top.Evidence) > 0 {
            for _, e := range top.Evidence {
                if e.Type == "similarity_features" {
                    fm := r.evidenceToFeatureMap(e.Value)
                    if len(fm) > 0 {
                        // compute dominant from map
                        bestName := ""
                        bestVal := -1.0
                        for name, val := range fm {
                            if val > bestVal {
                                bestVal = val
                                bestName = name
                            }
                        }
                        result.Metadata["runt_top_dominant_feature"] = map[string]interface{}{"name": bestName, "value": bestVal}
                    }
                    break
                }
            }
        }
    }
    result.Metadata["attack_thresholds"] = map[string]float64{
        "unicode":  r.config.UnicodeAttackThreshold,
        "keyboard": r.config.KeyboardAttackThreshold,
        "visual":   r.config.VisualAttackThreshold,
        "phonetic": r.config.PhoneticAttackThreshold,
    }
    result.Metadata["dep_cache_hits"] = int(atomic.LoadInt64(&r.depCacheHits))
    result.Metadata["dep_cache_misses"] = int(atomic.LoadInt64(&r.depCacheMisses))
    r.metrics.PackagesProcessed += len(packages)
    r.metrics.ThreatsDetected += len(result.Findings)
    r.metrics.ProcessingTime = time.Since(startTime)
    r.metrics.LastUpdated = time.Now()
    return result, nil
}

// SuspiciousPackage represents a potentially malicious package
type SuspiciousPackage struct {
	Name            string              `json:"name"`
	SimilarityScore float64             `json:"similarity_score"`
	Features        *SimilarityFeatures `json:"features"`
	AttackType      string              `json:"attack_type"`
}

// Core algorithm implementation

func (r *RUNTAlgorithm) initializeComponents() {
    r.initializeVisualSimilarity()
    r.initializePhoneticEncoder()
    r.initializeSemanticModel()
    r.initializeMixtureModel()
    r.loadKnownPackages()
    r.npmConnector = registry.NewNPMConnector(&registry.Registry{Name: "npm", URL: "https://registry.npmjs.org", Type: "npm", Enabled: true})
}

func (r *RUNTAlgorithm) initializeVisualSimilarity() {
    // Initialize visual similarity mappings for homoglyph detection
    r.visualSimilarityMap = map[rune][]rune{
        'a': {'à', 'á', 'â', 'ã', 'ä', 'å', 'α', 'а'},
        'e': {'è', 'é', 'ê', 'ë', 'е'},
        'i': {'ì', 'í', 'î', 'ï', 'і'},
        'o': {'ò', 'ó', 'ô', 'õ', 'ö', 'ο', 'о'},
        'u': {'ù', 'ú', 'û', 'ü'},
        'c': {'ç', 'с'},
        'p': {'р'},
        'x': {'х'},
        'y': {'у'},
        '0': {'О', 'о', 'Ο', 'ο'},
        '1': {'l', 'I', '|', 'і'},
    }
    r.visualReverseMap = make(map[rune]rune)
    for base, variants := range r.visualSimilarityMap {
        for _, v := range variants {
            r.visualReverseMap[v] = base
        }
    }
}

func (r *RUNTAlgorithm) initializePhoneticEncoder() {
	r.phoneticEncoder = &PhoneticEncoder{
		soundexMap: map[rune]rune{
			'b': '1', 'f': '1', 'p': '1', 'v': '1',
			'c': '2', 'g': '2', 'j': '2', 'k': '2', 'q': '2', 's': '2', 'x': '2', 'z': '2',
			'd': '3', 't': '3',
			'l': '4',
			'm': '5', 'n': '5',
			'r': '6',
		},
	}
}

func (r *RUNTAlgorithm) initializeSemanticModel() {
	// Initialize with basic semantic model
	// In production, this would load pre-trained embeddings
	r.semanticModel = &SemanticModel{
		embeddings: make(map[string][]float64),
		vocabulary: make(map[string]bool),
	}
}

func (r *RUNTAlgorithm) initializeMixtureModel() {
	r.mixtureModel = &BayesianMixtureModel{
		components: make([]MixtureComponent, r.config.MixtureComponents),
		weights:    make([]float64, r.config.MixtureComponents),
		trained:    false,
	}
}

func (r *RUNTAlgorithm) loadKnownPackages() {
	// Load known legitimate packages
	// This would typically load from a database or file
	knownPackages := []string{
		"react", "angular", "vue", "express", "lodash", "axios", "moment",
		"webpack", "babel", "eslint", "typescript", "jquery", "bootstrap",
		"numpy", "pandas", "requests", "flask", "django", "tensorflow",
	}

	for _, pkg := range knownPackages {
		r.knownPackages[pkg] = true
	}
}

func (r *RUNTAlgorithm) findSuspiciousPackages(packageName string) []SuspiciousPackage {
	suspicious := make([]SuspiciousPackage, 0)

	// Check against known packages
	for knownPkg := range r.knownPackages {
		if knownPkg == packageName {
			continue // Skip exact matches
		}

		features := r.computeAllSimilarityFeatures(packageName, knownPkg)
		overallScore := r.computeOverallSimilarity(features)

		if overallScore > r.config.OverallThreshold {
			attackType := r.classifyAttackType(features)

			suspicious = append(suspicious, SuspiciousPackage{
				Name:            knownPkg,
				SimilarityScore: overallScore,
				Features:        features,
				AttackType:      attackType,
			})
		}
	}

	// Sort by similarity score (descending)
	sort.Slice(suspicious, func(i, j int) bool {
		return suspicious[i].SimilarityScore > suspicious[j].SimilarityScore
	})

	// Return top 5 most suspicious
	if len(suspicious) > 5 {
		suspicious = suspicious[:5]
	}

	return suspicious
}

func (r *RUNTAlgorithm) computeAllSimilarityFeatures(name1, name2 string) *SimilarityFeatures {
	return &SimilarityFeatures{
		Levenshtein:    r.levenshteinSimilarity(name1, name2),
		JaroWinkler:    r.jaroWinklerSimilarity(name1, name2),
		Phonetic:       r.phoneticSimilarity(name1, name2),
		Visual:         r.visualSimilarity(name1, name2),
		Semantic:       r.semanticSimilarity(name1, name2),
		LCS:            r.lcsSimilarity(name1, name2),
		Hamming:        r.hammingSimilarity(name1, name2),
		Cosine:         r.cosineSimilarity(name1, name2),
		Jaccard:        r.jaccardSimilarity(name1, name2),
		NGram:          r.ngramSimilarity(name1, name2),
		KeyboardLayout: r.keyboardLayoutSimilarity(name1, name2),
		Unicode:        r.unicodeSimilarity(name1, name2),
	}
}

// Similarity metric implementations

func (r *RUNTAlgorithm) levenshteinSimilarity(s1, s2 string) float64 {
	distance := r.levenshteinDistance(s1, s2)
	maxLen := math.Max(float64(len(s1)), float64(len(s2)))
	if maxLen == 0 {
		return 1.0
	}
	return 1.0 - float64(distance)/maxLen
}

func (r *RUNTAlgorithm) levenshteinDistance(s1, s2 string) int {
	if len(s1) == 0 {
		return len(s2)
	}
	if len(s2) == 0 {
		return len(s1)
	}

	matrix := make([][]int, len(s1)+1)
	for i := range matrix {
		matrix[i] = make([]int, len(s2)+1)
		matrix[i][0] = i
	}

	for j := 0; j <= len(s2); j++ {
		matrix[0][j] = j
	}

	for i := 1; i <= len(s1); i++ {
		for j := 1; j <= len(s2); j++ {
			cost := 0
			if s1[i-1] != s2[j-1] {
				cost = 1
			}

			matrix[i][j] = min3(
				matrix[i-1][j]+1,      // deletion
				matrix[i][j-1]+1,      // insertion
				matrix[i-1][j-1]+cost, // substitution
			)
		}
	}

	return matrix[len(s1)][len(s2)]
}

func (r *RUNTAlgorithm) jaroWinklerSimilarity(s1, s2 string) float64 {
	// Simplified Jaro-Winkler implementation
	if s1 == s2 {
		return 1.0
	}

	len1, len2 := len(s1), len(s2)
	if len1 == 0 || len2 == 0 {
		return 0.0
	}

	// Calculate Jaro similarity (simplified)
	matches := 0
	for i := 0; i < min(len1, len2); i++ {
		if s1[i] == s2[i] {
			matches++
		}
	}

	jaro := float64(matches) / math.Max(float64(len1), float64(len2))

	// Add Winkler prefix bonus
	prefix := 0
	for i := 0; i < min(min(len1, len2), 4); i++ {
		if s1[i] == s2[i] {
			prefix++
		} else {
			break
		}
	}

	return jaro + (0.1 * float64(prefix) * (1.0 - jaro))
}

func (r *RUNTAlgorithm) phoneticSimilarity(s1, s2 string) float64 {
	soundex1 := r.phoneticEncoder.soundex(s1)
	soundex2 := r.phoneticEncoder.soundex(s2)

	if soundex1 == soundex2 {
		return 1.0
	}

	// Calculate similarity between soundex codes
	return r.levenshteinSimilarity(soundex1, soundex2)
}

func (r *RUNTAlgorithm) visualSimilarity(s1, s2 string) float64 {
	// Check for visual similarity using homoglyph mappings
	normalized1 := r.normalizeVisually(s1)
	normalized2 := r.normalizeVisually(s2)

	return r.levenshteinSimilarity(normalized1, normalized2)
}

func (r *RUNTAlgorithm) semanticSimilarity(s1, s2 string) float64 {
    a := strings.ToLower(s1)
    b := strings.ToLower(s2)
    if a == b {
        return 1.0
    }
    if len(a) == 0 || len(b) == 0 {
        return 0.0
    }
    split := func(s string) []string {
        tokens := strings.FieldsFunc(s, func(r rune) bool {
            return r == '-' || r == '_' || r == '.'
        })
        if len(tokens) == 0 {
            tokens = []string{s}
        }
        return tokens
    }
    t1 := split(a)
    t2 := split(b)
    used := make([]bool, len(t2))
    score := 0.0
    for _, x := range t1 {
        best := 0.0
        idx := -1
        for j, y := range t2 {
            if used[j] {
                continue
            }
            s := r.levenshteinSimilarity(x, y)
            if s > best {
                best = s
                idx = j
            }
        }
        if idx >= 0 {
            used[idx] = true
            score += best
        }
    }
    denom := float64(max(len(t1), len(t2)))
    if denom == 0 {
        return 0.0
    }
    tokenScore := score / denom
    strip := func(s string) string {
        return strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(s, "-", ""), "_", ""), ".", "")
    }
    strippedSim := r.levenshteinSimilarity(strip(a), strip(b))
    if strippedSim > tokenScore {
        return strippedSim
    }
    return tokenScore
}

func (r *RUNTAlgorithm) lcsSimilarity(s1, s2 string) float64 {
	lcs := r.longestCommonSubsequence(s1, s2)
	maxLen := math.Max(float64(len(s1)), float64(len(s2)))
	if maxLen == 0 {
		return 1.0
	}
	return float64(lcs) / maxLen
}

func (r *RUNTAlgorithm) hammingSimilarity(s1, s2 string) float64 {
	if len(s1) != len(s2) {
		return 0.0
	}

	matches := 0
	for i := 0; i < len(s1); i++ {
		if s1[i] == s2[i] {
			matches++
		}
	}

	return float64(matches) / float64(len(s1))
}

func (r *RUNTAlgorithm) cosineSimilarity(s1, s2 string) float64 {
	// Character frequency vectors
	freq1 := r.getCharFrequency(s1)
	freq2 := r.getCharFrequency(s2)

	return r.cosineDistance(freq1, freq2)
}

func (r *RUNTAlgorithm) jaccardSimilarity(s1, s2 string) float64 {
	set1 := r.getCharSet(s1)
	set2 := r.getCharSet(s2)

	intersection := 0
	union := len(set1)

	for char := range set2 {
		if set1[char] {
			intersection++
		} else {
			union++
		}
	}

	if union == 0 {
		return 1.0
	}

	return float64(intersection) / float64(union)
}

func (r *RUNTAlgorithm) ngramSimilarity(s1, s2 string) float64 {
	ngrams1 := r.getNGrams(s1, 2)
	ngrams2 := r.getNGrams(s2, 2)

	return r.jaccardSimilarityMaps(ngrams1, ngrams2)
}

func (r *RUNTAlgorithm) keyboardLayoutSimilarity(s1, s2 string) float64 {
    keyboard := r.getKeyboardMap()

    // Calculate similarity based on keyboard proximity
    return r.layoutBasedSimilarity(s1, s2, keyboard)
}

func (r *RUNTAlgorithm) getKeyboardMap() map[rune][]rune {
    return map[rune][]rune{
        '1': {'2', 'q'}, '2': {'1', '3', 'q', 'w'}, '3': {'2', '4', 'w', 'e'},
        '4': {'3', '5', 'e', 'r'}, '5': {'4', '6', 'r', 't'}, '6': {'5', '7', 't', 'y'},
        '7': {'6', '8', 'y', 'u'}, '8': {'7', '9', 'u', 'i'}, '9': {'8', '0', 'i', 'o'},
        '0': {'9', 'o', 'p'},
        'q': {'1', '2', 'w', 'a'},
        'w': {'q', 'e', 'a', 's', '2', '3'},
        'e': {'w', 'r', 's', 'd', '3', '4'},
        'r': {'e', 't', 'd', 'f', '4', '5'},
        't': {'r', 'y', 'f', 'g', '5', '6'},
        'y': {'t', 'u', 'g', 'h', '6', '7'},
        'u': {'y', 'i', 'h', 'j', '7', '8'},
        'i': {'u', 'o', 'j', 'k', '8', '9'},
        'o': {'i', 'p', 'k', 'l', '9', '0'},
        'p': {'o', 'l'},
        'a': {'q', 'w', 's', 'z'},
        's': {'a', 'w', 'e', 'd', 'z', 'x'},
        'd': {'s', 'e', 'r', 'f', 'x', 'c'},
        'f': {'d', 'r', 't', 'g', 'c', 'v'},
        'g': {'f', 't', 'y', 'h', 'v', 'b'},
        'h': {'g', 'y', 'u', 'j', 'b', 'n'},
        'j': {'h', 'u', 'i', 'k', 'n', 'm'},
        'k': {'j', 'i', 'o', 'l', 'm'},
        'l': {'k', 'o', 'p'},
        'z': {'a', 's', 'x'},
        'x': {'z', 's', 'd', 'c'},
        'c': {'x', 'd', 'f', 'v'},
        'v': {'c', 'f', 'g', 'b'},
        'b': {'v', 'g', 'h', 'n'},
        'n': {'b', 'h', 'j', 'm'},
        'm': {'n', 'j', 'k'},
    }
}

func (r *RUNTAlgorithm) keyboardAdjacencyDetails(s1, s2 string) []string {
    km := r.getKeyboardMap()
    a := []rune(strings.ToLower(s1))
    b := []rune(strings.ToLower(s2))
    n := len(a)
    if len(b) < n {
        n = len(b)
    }
    details := make([]string, 0)
    isAdj := func(x, y rune) bool {
        if x == y { return true }
        adj := km[x]
        for _, k := range adj { if k == y { return true } }
        return false
    }
    for i := 0; i < n; i++ {
        if isAdj(a[i], b[i]) {
            details = append(details, fmt.Sprintf("%d:%c~%c", i, a[i], b[i]))
            continue
        }
        if i+1 < n && isAdj(a[i], b[i+1]) {
            details = append(details, fmt.Sprintf("%d->%d:%c~%c", i, i+1, a[i], b[i+1]))
            continue
        }
        if i-1 >= 0 && isAdj(a[i], b[i-1]) {
            details = append(details, fmt.Sprintf("%d->%d:%c~%c", i, i-1, a[i], b[i-1]))
            continue
        }
    }
    return details
}

func (r *RUNTAlgorithm) getScripts(s string) []string {
    set := make(map[string]bool)
    for _, r := range []rune(s) {
        switch {
        case unicode.Is(unicode.Latin, r):
            set["Latin"] = true
        case unicode.Is(unicode.Cyrillic, r):
            set["Cyrillic"] = true
        case unicode.Is(unicode.Greek, r):
            set["Greek"] = true
        default:
            if unicode.IsDigit(r) {
                set["Digit"] = true
            } else if unicode.IsLetter(r) {
                set["OtherLetter"] = true
            } else {
                set["Other"] = true
            }
        }
    }
    out := make([]string, 0, len(set))
    for k := range set { out = append(out, k) }
    sort.Strings(out)
    return out
}

func (r *RUNTAlgorithm) unicodeDetails(s1, s2 string) map[string]interface{} {
    norm1 := r.normalizeVisually(s1)
    changed := func(orig, norm string) float64 {
        o := []rune(orig)
        n := []rune(norm)
        m := len(o)
        if len(n) < m { m = len(n) }
        if m == 0 { return 0.0 }
        c := 0.0
        for i := 0; i < m; i++ { if o[i] != n[i] { c += 1.0 } }
        return c / float64(m)
    }
    nonStandard := func(s string) float64 {
        if len(s) == 0 { return 0.0 }
        allowed := func(r rune) bool { return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' || r == '.' }
        cnt := 0.0
        runes := []rune(s)
        for _, r := range runes { if !allowed(r) { cnt += 1.0 } }
        return cnt / float64(len(runes))
    }
    scripts1 := r.getScripts(s1)
    scripts2 := r.getScripts(s2)
    return map[string]interface{}{
        "changed_ratio": changed(s1, norm1),
        "mixed_scripts": len(scripts1) > 1 || len(scripts2) > 1,
        "non_standard_ratio": math.Max(nonStandard(s1), nonStandard(s2)),
        "scripts1": scripts1,
        "scripts2": scripts2,
    }
}

func (r *RUNTAlgorithm) semanticDetails(s1, s2 string) map[string]interface{} {
    split := func(s string) []string {
        t := strings.FieldsFunc(strings.ToLower(s), func(r rune) bool {
            return r == '-' || r == '_' || r == '.'
        })
        if len(t) == 0 { t = []string{s} }
        return t
    }
    t1 := split(s1)
    t2 := split(s2)
    matches := make([][2]string, 0)
    used := make([]bool, len(t2))
    for _, a := range t1 {
        best := -1
        bestScore := 0.0
        for j, b := range t2 {
            if used[j] { continue }
            s := r.levenshteinSimilarity(a, b)
            if s > bestScore { bestScore = s; best = j }
        }
        if best >= 0 {
            used[best] = true
            matches = append(matches, [2]string{a, t2[best]})
        }
    }
    strip := func(s string) string { return strings.ReplaceAll(strings.ReplaceAll(strings.ReplaceAll(s, "-", ""), "_", ""), ".", "") }
    return map[string]interface{}{
        "tokens1": t1,
        "tokens2": t2,
        "matched_pairs": matches,
        "stripped_similarity": r.levenshteinSimilarity(strip(s1), strip(s2)),
    }
}

func (r *RUNTAlgorithm) unicodeSimilarity(s1, s2 string) float64 {
	if !r.config.EnableUnicodeAnalysis {
		return 0.0
	}

	// Analyze Unicode categories and scripts
	return r.analyzeUnicodeProperties(s1, s2)
}

// Helper methods

func (r *RUNTAlgorithm) computeOverallSimilarity(features *SimilarityFeatures) float64 {
    // Weighted combination of all features
    weights := []float64{0.12, 0.12, 0.08, 0.10, 0.16, 0.08, 0.03, 0.04, 0.04, 0.04, 0.10, 0.09}
    values := []float64{
        features.Levenshtein, features.JaroWinkler, features.Phonetic,
        features.Visual, features.Semantic, features.LCS, features.Hamming,
        features.Cosine, features.Jaccard, features.NGram,
        features.KeyboardLayout, features.Unicode,
    }

	var weightedSum, totalWeight float64
	for i, weight := range weights {
		if i < len(values) {
			weightedSum += weight * values[i]
			totalWeight += weight
		}
	}

	if totalWeight == 0 {
		return 0.0
	}

	return weightedSum / totalWeight
}

func (r *RUNTAlgorithm) computeConfidence(features *SimilarityFeatures) float64 {
    if features == nil {
        return 0.0
    }
    vals := []float64{
        features.Levenshtein,
        features.JaroWinkler,
        features.Phonetic,
        features.Visual,
        features.Semantic,
        features.LCS,
        features.Hamming,
        features.Cosine,
        features.Jaccard,
        features.NGram,
        features.KeyboardLayout,
        features.Unicode,
    }
    if r.mixtureModel != nil {
        c := r.mixtureModel.computeProbability(vals)
        if c >= 0.0 && c <= 1.0 {
            return c
        }
    }
    return r.computeOverallSimilarity(features)
}

func (r *RUNTAlgorithm) featureContributions(features *SimilarityFeatures) map[string]float64 {
    weights := []float64{0.12, 0.12, 0.08, 0.10, 0.16, 0.08, 0.03, 0.04, 0.04, 0.04, 0.10, 0.09}
    values := []float64{
        features.Levenshtein, features.JaroWinkler, features.Phonetic,
        features.Visual, features.Semantic, features.LCS, features.Hamming,
        features.Cosine, features.Jaccard, features.NGram,
        features.KeyboardLayout, features.Unicode,
    }
    names := []string{
        "levenshtein", "jaro_winkler", "phonetic", "visual",
        "semantic", "lcs", "hamming", "cosine", "jaccard",
        "ngram", "keyboard_layout", "unicode",
    }
    out := make(map[string]float64)
    for i := range values {
        out[names[i]] = values[i] * weights[i]
    }
    return out
}

func (r *RUNTAlgorithm) dominantFeature(features *SimilarityFeatures) (string, float64) {
    names := []string{
        "levenshtein", "jaro_winkler", "phonetic", "visual",
        "semantic", "lcs", "hamming", "cosine", "jaccard",
        "ngram", "keyboard_layout", "unicode",
    }
    values := []float64{
        features.Levenshtein, features.JaroWinkler, features.Phonetic,
        features.Visual, features.Semantic, features.LCS, features.Hamming,
        features.Cosine, features.Jaccard, features.NGram, features.KeyboardLayout,
        features.Unicode,
    }
    bestName := ""
    bestVal := -1.0
    for i, v := range values {
        if v > bestVal {
            bestVal = v
            bestName = names[i]
        }
    }
    return bestName, bestVal
}

func (r *RUNTAlgorithm) topContributions(contrib map[string]float64, n int) map[string]float64 {
    if n <= 0 || len(contrib) == 0 {
        return map[string]float64{}
    }
    type kv struct{ k string; v float64 }
    arr := make([]kv, 0, len(contrib))
    for k, v := range contrib { arr = append(arr, kv{k, v}) }
    sort.Slice(arr, func(i, j int) bool { return arr[i].v > arr[j].v })
    out := make(map[string]float64)
    limit := n
    if len(arr) < n { limit = len(arr) }
    for i := 0; i < limit; i++ {
        out[arr[i].k] = arr[i].v
    }
    return out
}

// getDependencies retrieves dependency names from NPM registry
func (r *RUNTAlgorithm) getDependencies(ctx context.Context, name string) []string {
    if r.npmConnector == nil || name == "" {
        return nil
    }
    // Check cache first (TTL 10 minutes)
    r.depMu.RLock()
    deps, ok := r.depCache[name]
    ts := r.depCacheTS[name]
    r.depMu.RUnlock()
    ttl := time.Duration(r.config.DependencyCacheTTLMinutes) * time.Minute
    if ttl <= 0 {
        ttl = 10 * time.Minute
    }
    if ok && time.Since(ts) < ttl {
        atomic.AddInt64(&r.depCacheHits, 1)
        return deps
    }

    c, cancel := context.WithTimeout(ctx, 2*time.Second)
    defer cancel()
    info, err := r.npmConnector.GetPackageInfo(c, name, "latest")
    if err != nil || info == nil {
        atomic.AddInt64(&r.depCacheMisses, 1)
        return nil
    }
    // Update cache
    r.depMu.Lock()
    r.depCache[name] = info.Dependencies
    r.depCacheTS[name] = time.Now()
    r.depMu.Unlock()
    atomic.AddInt64(&r.depCacheMisses, 1)
    return info.Dependencies
}

// Exported helpers for testing and external use
func (r *RUNTAlgorithm) ComputeAllSimilarityFeatures(name1, name2 string) *SimilarityFeatures {
    return r.computeAllSimilarityFeatures(name1, name2)
}

func (r *RUNTAlgorithm) ClassifyAttackType(features *SimilarityFeatures) string {
    return r.classifyAttackType(features)
}

func (r *RUNTAlgorithm) computeBayesianThreatScore(features *SimilarityFeatures) float64 {
	if !r.mixtureModel.trained {
		// Use simple weighted score if model not trained
		return r.computeOverallSimilarity(features)
	}

	// Convert features to vector
	featureVector := []float64{
		features.Levenshtein, features.JaroWinkler, features.Phonetic,
		features.Visual, features.Semantic, features.LCS,
	}

	// Compute probability under mixture model
	return r.mixtureModel.computeProbability(featureVector)
}


func (r *RUNTAlgorithm) classifyAttackType(features *SimilarityFeatures) string {
    if features.Unicode > r.config.UnicodeAttackThreshold {
        return "UNICODE_CONFUSION"
    }
    if features.KeyboardLayout > r.config.KeyboardAttackThreshold {
        return "KEYBOARD_TYPO"
    }
    if features.Visual > r.config.VisualAttackThreshold {
        return "HOMOGLYPH_ATTACK"
    }
    if features.Phonetic > r.config.PhoneticAttackThreshold {
        return "PHONETIC_SQUATTING"
    }
    return "GENERAL_TYPOSQUATTING"
}

func (r *RUNTAlgorithm) getSeverity(score float64) string {
	if score > 0.9 {
		return "CRITICAL"
	}
	if score > 0.8 {
		return "HIGH"
	}
	if score > 0.6 {
		return "MEDIUM"
	}
	return "LOW"
}

// Utility functions

func min3(a, b, c int) int {
	if a < b && a < c {
		return a
	}
	if b < c {
		return b
	}
	return c
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Placeholder implementations for complex methods

func (pe *PhoneticEncoder) soundex(s string) string {
	if len(s) == 0 {
		return ""
	}

	// Simplified Soundex implementation
	result := strings.ToUpper(string(s[0]))

	for i := 1; i < len(s) && len(result) < 4; i++ {
		char := unicode.ToLower(rune(s[i]))
		if code, exists := pe.soundexMap[char]; exists {
			if len(result) == 1 || result[len(result)-1] != byte(code) {
				result += string(code)
			}
		}
	}

	// Pad with zeros
	for len(result) < 4 {
		result += "0"
	}

	return result
}

func (r *RUNTAlgorithm) normalizeVisually(s string) string {
    var result strings.Builder
    for _, char := range s {
        if base, ok := r.visualReverseMap[char]; ok {
            result.WriteRune(base)
        } else {
            result.WriteRune(char)
        }
    }
    return result.String()
}

func (r *RUNTAlgorithm) longestCommonSubsequence(s1, s2 string) int {
	m, n := len(s1), len(s2)
	dp := make([][]int, m+1)
	for i := range dp {
		dp[i] = make([]int, n+1)
	}

	for i := 1; i <= m; i++ {
		for j := 1; j <= n; j++ {
			if s1[i-1] == s2[j-1] {
				dp[i][j] = dp[i-1][j-1] + 1
			} else {
				dp[i][j] = max(dp[i-1][j], dp[i][j-1])
			}
		}
	}

	return dp[m][n]
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func (r *RUNTAlgorithm) getCharFrequency(s string) map[rune]int {
	freq := make(map[rune]int)
	for _, char := range s {
		freq[char]++
	}
	return freq
}

func (r *RUNTAlgorithm) getCharSet(s string) map[rune]bool {
	set := make(map[rune]bool)
	for _, char := range s {
		set[char] = true
	}
	return set
}

func (r *RUNTAlgorithm) cosineDistance(freq1, freq2 map[rune]int) float64 {
	// Simplified cosine similarity
	var dotProduct, norm1, norm2 float64

	allChars := make(map[rune]bool)
	for char := range freq1 {
		allChars[char] = true
	}
	for char := range freq2 {
		allChars[char] = true
	}

	for char := range allChars {
		f1 := float64(freq1[char])
		f2 := float64(freq2[char])

		dotProduct += f1 * f2
		norm1 += f1 * f1
		norm2 += f2 * f2
	}

	if norm1 == 0 || norm2 == 0 {
		return 0.0
	}

	return dotProduct / (math.Sqrt(norm1) * math.Sqrt(norm2))
}

func (r *RUNTAlgorithm) getNGrams(s string, n int) map[string]int {
	ngrams := make(map[string]int)

	if len(s) < n {
		ngrams[s] = 1
		return ngrams
	}

	for i := 0; i <= len(s)-n; i++ {
		ngram := s[i : i+n]
		ngrams[ngram]++
	}

	return ngrams
}

func (r *RUNTAlgorithm) jaccardSimilarityMaps(map1, map2 map[string]int) float64 {
	intersection := 0
	union := len(map1)

	for key := range map2 {
		if map1[key] > 0 {
			intersection++
		} else {
			union++
		}
	}

	if union == 0 {
		return 1.0
	}

	return float64(intersection) / float64(union)
}

func (r *RUNTAlgorithm) layoutBasedSimilarity(s1, s2 string, keyboard map[rune][]rune) float64 {
    if len(s1) == 0 || len(s2) == 0 {
        return 0.0
    }
    runes1 := []rune(strings.ToLower(s1))
    runes2 := []rune(strings.ToLower(s2))

    n := len(runes1)
    if len(runes2) < n {
        n = len(runes2)
    }

    matches := 0.0
    total := float64(n)

    isAdjacent := func(a, b rune) bool {
        if a == b {
            return true
        }
        adj, ok := keyboard[a]
        if !ok {
            return false
        }
        for _, k := range adj {
            if k == b {
                return true
            }
        }
        return false
    }

    for i := 0; i < n; i++ {
        if isAdjacent(runes1[i], runes2[i]) {
            matches += 1.0
            continue
        }
        if i+1 < n && isAdjacent(runes1[i], runes2[i+1]) {
            matches += 0.6
            continue
        }
        if i-1 >= 0 && isAdjacent(runes1[i], runes2[i-1]) {
            matches += 0.6
            continue
        }
    }

    score := matches / total
    if score > 0.95 {
        score = 0.95
    }
    if score < 0.0 {
        score = 0.0
    }
    if score > 1.0 {
        score = 1.0
    }
    return score
}

func (r *RUNTAlgorithm) analyzeUnicodeProperties(s1, s2 string) float64 {
    if len(s1) == 0 && len(s2) == 0 {
        return 0.0
    }
    norm1 := r.normalizeVisually(s1)
    norm2 := r.normalizeVisually(s2)
    changed := func(orig, norm string) float64 {
        if len(orig) == 0 {
            return 0.0
        }
        o := []rune(orig)
        n := []rune(norm)
        m := len(o)
        if len(n) < m {
            m = len(n)
        }
        c := 0.0
        for i := 0; i < m; i++ {
            if o[i] != n[i] {
                c += 1.0
            }
        }
        return c / float64(m)
    }
    scriptSet := func(s string) map[string]bool {
        set := make(map[string]bool)
        for _, r := range []rune(s) {
            switch {
            case unicode.Is(unicode.Latin, r):
                set["Latin"] = true
            case unicode.Is(unicode.Cyrillic, r):
                set["Cyrillic"] = true
            case unicode.Is(unicode.Greek, r):
                set["Greek"] = true
            default:
                if unicode.IsDigit(r) {
                    set["Digit"] = true
                } else if unicode.IsLetter(r) {
                    set["OtherLetter"] = true
                } else {
                    set["Other"] = true
                }
            }
        }
        return set
    }
    ss1 := scriptSet(s1)
    ss2 := scriptSet(s2)
    mixed := func(a, b map[string]bool) bool {
        combined := make(map[string]bool)
        for k := range a {
            combined[k] = true
        }
        for k := range b {
            combined[k] = true
        }
        count := 0
        for k := range combined {
            if k != "Digit" {
                count++
            }
        }
        return count > 1 && !(combined["Latin"] && count == 1)
    }
    nonStandardRatio := func(s string) float64 {
        if len(s) == 0 {
            return 0.0
        }
        allowed := func(r rune) bool {
            return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '-' || r == '_' || r == '.'
        }
        c := 0.0
        for _, r := range []rune(s) {
            if !allowed(r) {
                c += 1.0
            }
        }
        return c / float64(len([]rune(s)))
    }
    ch := math.Max(changed(s1, norm1), changed(s2, norm2))
    mix := 0.0
    if mixed(ss1, ss2) {
        mix = 1.0
    }
    ns := math.Max(nonStandardRatio(s1), nonStandardRatio(s2))
    score := 0.2*ch + 0.7*mix + 0.1*ns
    if score < 0.0 {
        score = 0.0
    }
    if score > 1.0 {
        score = 1.0
    }
    return score
}

func (r *RUNTAlgorithm) calculateVariance(values []float64) float64 {
	if len(values) == 0 {
		return 0.0
	}

	// Calculate mean
	var sum float64
	for _, v := range values {
		sum += v
	}
	mean := sum / float64(len(values))

	// Calculate variance
	var variance float64
	for _, v := range values {
		variance += (v - mean) * (v - mean)
	}

	return variance / float64(len(values))
}

func (bmm *BayesianMixtureModel) computeProbability(features []float64) float64 {
    if len(features) == 0 {
        return 0.0
    }
    if !bmm.trained || len(bmm.components) == 0 {
        sum := 0.0
        for _, v := range features {
            sum += v
        }
        avg := sum / float64(len(features))
        if avg < 0.0 {
            return 0.0
        }
        if avg > 1.0 {
            return 1.0
        }
        return avg
    }
    totalWeight := 0.0
    weighted := 0.0
    for i, c := range bmm.components {
        w := c.weight
        if i < len(bmm.weights) && bmm.weights[i] > 0 {
            w = bmm.weights[i]
        }
        if w <= 0 {
            continue
        }
        if len(c.mean) != len(features) {
            continue
        }
        d2 := 0.0
        for j := range features {
            diff := features[j] - c.mean[j]
            d2 += diff * diff
        }
        like := math.Exp(-d2)
        weighted += w * like
        totalWeight += w
    }
    if totalWeight == 0 {
        return 0.0
    }
    prob := weighted / totalWeight
    if prob < 0.0 {
        prob = 0.0
    }
    if prob > 1.0 {
        prob = 1.0
    }
    return prob
}

// Reset resets the algorithm state
func (r *RUNTAlgorithm) Reset() error {
    // Reset metrics
    r.metrics = &AlgorithmMetrics{
        ProcessingTime: 0,
    }

    // Reset known packages
    r.knownPackages = make(map[string]bool)

    // Clear dependency cache
    r.depMu.Lock()
    r.depCache = make(map[string][]string)
    r.depCacheTS = make(map[string]time.Time)
    r.depMu.Unlock()
    atomic.StoreInt64(&r.depCacheHits, 0)
    atomic.StoreInt64(&r.depCacheMisses, 0)

    // Reinitialize components
    r.initializeComponents()

    return nil
}
func (r *RUNTAlgorithm) recursiveAnalyzeDependencies(ctx context.Context, name string, depth, maxDepth int, visited map[string]bool, analyzedGlobal map[string]bool, simCache map[string][]SuspiciousPackage) []Finding {
    if depth >= maxDepth || visited[name] {
        return nil
    }
    visited[name] = true
    if analyzedGlobal[name] {
        return nil
    }
    deps := r.getDependencies(ctx, name)
    findings := make([]Finding, 0)
    for _, dep := range deps {
        featuresList := r.findSuspiciousPackagesCached(dep, simCache)
        for _, sp := range featuresList {
            if sp.SimilarityScore > r.config.OverallThreshold {
                evidences := []Evidence{
                    {Type: "parent_package", Description: "Dependency parent", Value: name, Score: sp.SimilarityScore},
                    {Type: "target_package", Description: "Suspicious dependency", Value: sp.Name, Score: sp.SimilarityScore},
                    {Type: "similarity_features", Description: "Similarity analysis features", Value: sp.Features, Score: sp.SimilarityScore},
                    {Type: "attack_type", Description: "Type of typosquatting attack", Value: sp.AttackType, Score: 0.8},
                }
                if sp.Features.KeyboardLayout > 0.7 {
                    evidences = append(evidences, Evidence{Type: "keyboard_detail", Description: "Adjacent key matches and transpositions", Value: r.keyboardAdjacencyDetails(dep, sp.Name), Score: sp.Features.KeyboardLayout})
                }
                if sp.Features.Unicode > 0.7 {
                    evidences = append(evidences, Evidence{Type: "unicode_detail", Description: "Unicode script and visual normalization analysis", Value: r.unicodeDetails(dep, sp.Name), Score: sp.Features.Unicode})
                }
                dn2, dv2 := r.dominantFeature(sp.Features)
                evidences = append(evidences,
                    Evidence{Type: "feature_contributions", Description: "Weighted contributions to overall similarity", Value: r.featureContributions(sp.Features), Score: sp.SimilarityScore},
                    Evidence{Type: "dominant_feature", Description: "Highest raw feature contributing to detection", Value: map[string]interface{}{"name": dn2, "value": dv2}, Score: dv2},
                    Evidence{Type: "similarity_summary", Description: "Top feature contributions", Value: r.topContributions(r.featureContributions(sp.Features), 3), Score: sp.SimilarityScore},
                )
                findings = append(findings, Finding{
                    ID:              fmt.Sprintf("runt_dep_typosquatting_%s_%s", name, dep),
                    Package:         dep,
                    Type:            "TYPOSQUATTING_DETECTED",
                    Severity:        r.getSeverity(r.computeConfidence(sp.Features)),
                    Message:         fmt.Sprintf("%s: dependency '%s' in '%s' ~ '%s' (confidence=%.2f)", sp.AttackType, dep, name, sp.Name, r.computeConfidence(sp.Features)),
                    Confidence:      r.computeConfidence(sp.Features),
                    DetectedAt:      time.Now().UTC(),
                    DetectionMethod: "runt_dependency_similarity",
                    Evidence:        evidences,
                })
            }
        }
        sub := r.recursiveAnalyzeDependencies(ctx, dep, depth+1, maxDepth, visited, analyzedGlobal, simCache)
        if len(sub) > 0 {
            findings = append(findings, sub...)
        }
    }
    analyzedGlobal[name] = true
    return findings
}

func (r *RUNTAlgorithm) findSuspiciousPackagesCached(packageName string, cache map[string][]SuspiciousPackage) []SuspiciousPackage {
    if v, ok := cache[packageName]; ok {
        return v
    }
    v := r.findSuspiciousPackages(packageName)
    cache[packageName] = v
    return v
}
func (r *RUNTAlgorithm) computeAttackSummary(findings []Finding) map[string]int {
    m := make(map[string]int)
    for _, f := range findings {
        m[f.Type]++
        for _, e := range f.Evidence {
            if e.Type == "attack_type" {
                if s, ok := e.Value.(string); ok {
                    m[s]++
                }
            }
        }
    }
    return m
}

func (r *RUNTAlgorithm) computeEvidenceSummary(findings []Finding) map[string]int {
    summary := make(map[string]int)
    for _, f := range findings {
        for _, e := range f.Evidence {
            summary[e.Type]++
        }
    }
    return summary
}
func (r *RUNTAlgorithm) evidenceToFeatureMap(v interface{}) map[string]float64 {
    out := make(map[string]float64)
    switch t := v.(type) {
    case *SimilarityFeatures:
        out["levenshtein"] = t.Levenshtein
        out["jaro_winkler"] = t.JaroWinkler
        out["phonetic"] = t.Phonetic
        out["visual"] = t.Visual
        out["semantic"] = t.Semantic
        out["lcs"] = t.LCS
        out["hamming"] = t.Hamming
        out["cosine"] = t.Cosine
        out["jaccard"] = t.Jaccard
        out["ngram"] = t.NGram
        out["keyboard_layout"] = t.KeyboardLayout
        out["unicode"] = t.Unicode
    case map[string]float64:
        for k, val := range t {
            out[k] = val
        }
    case map[string]interface{}:
        for k, v := range t {
            switch vv := v.(type) {
            case float64:
                out[k] = vv
            case int:
                out[k] = float64(vv)
            case int64:
                out[k] = float64(vv)
            default:
            }
        }
    default:
    }
    return out
}

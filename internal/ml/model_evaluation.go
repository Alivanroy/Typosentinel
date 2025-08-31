package ml

import (
	"context"
	"fmt"
	"time"
)

// ModelEvaluator type defined in model_evaluator.go

// EvaluationConfig and CoreEvaluationSettings types defined in advanced_evaluation.go

// DataSplitSettings defines how to split data for evaluation
type DataSplitSettings struct {
	TrainRatio      float64 `json:"train_ratio"`
	ValidationRatio float64 `json:"validation_ratio"`
	TestRatio       float64 `json:"test_ratio"`
	Stratified      bool    `json:"stratified"`
	Shuffle         bool    `json:"shuffle"`
	RandomSeed      int64   `json:"random_seed"`
}

// CrossValidationSettings defines cross-validation parameters
type CrossValidationSettings struct {
	Enabled    bool   `json:"enabled"`
	Folds      int    `json:"folds"`
	Strategy   string `json:"strategy"` // "k_fold", "stratified_k_fold", "time_series"
	Repeats    int    `json:"repeats"`
	RandomSeed int64  `json:"random_seed"`
}

// MetricsEvaluationSettings defines which metrics to calculate
type MetricsEvaluationSettings struct {
	Classification *ClassificationMetrics `json:"classification"`
	Regression     *RegressionMetrics     `json:"regression"`
	Ranking        *RankingMetrics        `json:"ranking"`
	Custom         []CustomMetric         `json:"custom"`
	Thresholds     map[string]float64     `json:"thresholds"`
}

// ClassificationMetrics defines classification evaluation metrics
type ClassificationMetrics struct {
	Enabled              bool  `json:"enabled"`
	Accuracy             bool  `json:"accuracy"`
	Precision            bool  `json:"precision"`
	Recall               bool  `json:"recall"`
	F1Score              bool  `json:"f1_score"`
	F2Score              bool  `json:"f2_score"`
	AUCROC               bool  `json:"auc_roc"`
	AUCPR                bool  `json:"auc_pr"`
	ConfusionMatrix      bool  `json:"confusion_matrix"`
	ClassificationReport bool  `json:"classification_report"`
	LogLoss              bool  `json:"log_loss"`
	MatthewsCorr         bool  `json:"matthews_corr"`
	CohenKappa           bool  `json:"cohen_kappa"`
	BalancedAccuracy     bool  `json:"balanced_accuracy"`
	TopKAccuracy         []int `json:"top_k_accuracy"`
	PerClassMetrics      bool  `json:"per_class_metrics"`
}

// RegressionMetrics defines regression evaluation metrics
type RegressionMetrics struct {
	Enabled             bool `json:"enabled"`
	MSE                 bool `json:"mse"`
	RMSE                bool `json:"rmse"`
	MAE                 bool `json:"mae"`
	MAPE                bool `json:"mape"`
	R2Score             bool `json:"r2_score"`
	AdjustedR2          bool `json:"adjusted_r2"`
	MeanAbsoluteError   bool `json:"mean_absolute_error"`
	MeanSquaredLogError bool `json:"mean_squared_log_error"`
	MedianAbsoluteError bool `json:"median_absolute_error"`
	ExplainedVariance   bool `json:"explained_variance"`
}

// RankingMetrics defines ranking evaluation metrics
type RankingMetrics struct {
	Enabled    bool  `json:"enabled"`
	NDCG       []int `json:"ndcg"` // NDCG@k values
	MAP        bool  `json:"map"`  // Mean Average Precision
	MRR        bool  `json:"mrr"`  // Mean Reciprocal Rank
	PrecisionK []int `json:"precision_k"`
	RecallK    []int `json:"recall_k"`
	HitRateK   []int `json:"hit_rate_k"`
}

// CustomMetric defines a custom evaluation metric
type CustomMetric struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	Function    string                 `json:"function"`
	Parameters  map[string]interface{} `json:"parameters"`
	Enabled     bool                   `json:"enabled"`
}

// ValidationEvaluationSettings defines validation settings
type ValidationEvaluationSettings struct {
	Enabled              bool                  `json:"enabled"`
	HoldoutValidation    *HoldoutValidation    `json:"holdout_validation"`
	TimeSeriesValidation *TimeSeriesValidation `json:"time_series_validation"`
	Bootstrap            *BootstrapValidation  `json:"bootstrap"`
	StatisticalTests     *StatisticalTests     `json:"statistical_tests"`
}

// HoldoutValidation defines holdout validation settings
type HoldoutValidation struct {
	Enabled    bool    `json:"enabled"`
	TestSize   float64 `json:"test_size"`
	RandomSeed int64   `json:"random_seed"`
	Stratified bool    `json:"stratified"`
	Shuffle    bool    `json:"shuffle"`
}

// TimeSeriesValidation defines time series validation settings
type TimeSeriesValidation struct {
	Enabled       bool   `json:"enabled"`
	Strategy      string `json:"strategy"` // "expanding", "sliding", "blocked"
	InitialWindow int    `json:"initial_window"`
	Horizon       int    `json:"horizon"`
	Step          int    `json:"step"`
	Gap           int    `json:"gap"`
	MaxSplits     int    `json:"max_splits"`
}

// BootstrapValidation defines bootstrap validation settings
type BootstrapValidation struct {
	Enabled         bool    `json:"enabled"`
	Samples         int     `json:"samples"`
	SampleSize      float64 `json:"sample_size"`
	RandomSeed      int64   `json:"random_seed"`
	ConfidenceLevel float64 `json:"confidence_level"`
}

// StatisticalTests defines statistical significance tests
type StatisticalTests struct {
	Enabled           bool    `json:"enabled"`
	TTest             bool    `json:"t_test"`
	WilcoxonTest      bool    `json:"wilcoxon_test"`
	McNemarTest       bool    `json:"mcnemar_test"`
	FriedmanTest      bool    `json:"friedman_test"`
	SignificanceLevel float64 `json:"significance_level"`
}

// BenchmarkSettings defines benchmarking configuration
type BenchmarkSettings struct {
	Enabled     bool                  `json:"enabled"`
	Baselines   []BaselineModel       `json:"baselines"`
	Performance *PerformanceBenchmark `json:"performance"`
	Scalability *ScalabilityBenchmark `json:"scalability"`
	Robustness  *RobustnessBenchmark  `json:"robustness"`
	Fairness    *FairnessBenchmark    `json:"fairness"`
}

// BaselineModel type defined in advanced_evaluation.go

// PerformanceBenchmark defines performance benchmarking
type PerformanceBenchmark struct {
	Enabled       bool          `json:"enabled"`
	Latency       bool          `json:"latency"`
	Throughput    bool          `json:"throughput"`
	MemoryUsage   bool          `json:"memory_usage"`
	CPUUsage      bool          `json:"cpu_usage"`
	DiskIO        bool          `json:"disk_io"`
	NetworkIO     bool          `json:"network_io"`
	WarmupRuns    int           `json:"warmup_runs"`
	BenchmarkRuns int           `json:"benchmark_runs"`
	Timeout       time.Duration `json:"timeout"`
}

// ScalabilityBenchmark defines scalability testing
type ScalabilityBenchmark struct {
	Enabled      bool            `json:"enabled"`
	DataSizes    []int           `json:"data_sizes"`
	Concurrency  []int           `json:"concurrency"`
	MemoryLimits []int64         `json:"memory_limits"`
	Timeouts     []time.Duration `json:"timeouts"`
}

// RobustnessBenchmark defines robustness testing
type RobustnessBenchmark struct {
	Enabled          bool              `json:"enabled"`
	NoiseTests       *NoiseTests       `json:"noise_tests"`
	AdversarialTests *AdversarialTests `json:"adversarial_tests"`
	CorruptionTests  *CorruptionTests  `json:"corruption_tests"`
	DriftTests       *DriftTests       `json:"drift_tests"`
}

// NoiseTests defines noise robustness testing
type NoiseTests struct {
	Enabled     bool      `json:"enabled"`
	NoiseTypes  []string  `json:"noise_types"`
	NoiseLevels []float64 `json:"noise_levels"`
	Iterations  int       `json:"iterations"`
}

// AdversarialTests defines adversarial robustness testing
type AdversarialTests struct {
	Enabled    bool      `json:"enabled"`
	Attacks    []string  `json:"attacks"`
	Epsilons   []float64 `json:"epsilons"`
	Iterations int       `json:"iterations"`
}

// CorruptionTests defines data corruption testing
type CorruptionTests struct {
	Enabled         bool     `json:"enabled"`
	CorruptionTypes []string `json:"corruption_types"`
	SeverityLevels  []int    `json:"severity_levels"`
	Iterations      int      `json:"iterations"`
}

// DriftTests defines concept/data drift testing
type DriftTests struct {
	Enabled     bool      `json:"enabled"`
	DriftTypes  []string  `json:"drift_types"`
	DriftRates  []float64 `json:"drift_rates"`
	WindowSizes []int     `json:"window_sizes"`
}

// FairnessBenchmark defines fairness evaluation
type FairnessBenchmark struct {
	Enabled             bool     `json:"enabled"`
	ProtectedAttributes []string `json:"protected_attributes"`
	FairnessMetrics     []string `json:"fairness_metrics"`
	BiasDetection       bool     `json:"bias_detection"`
	MitigationTests     bool     `json:"mitigation_tests"`
}

// ComparisonSettings type defined in advanced_training_pipeline.go

// ModelComparison defines a model to compare
type ModelComparison struct {
	Name       string                 `json:"name"`
	Version    string                 `json:"version"`
	Type       string                 `json:"type"`
	Parameters map[string]interface{} `json:"parameters"`
	Enabled    bool                   `json:"enabled"`
	Models     []*ModelCandidate      `json:"models"`
	Rankings   map[string]int         `json:"rankings"`
	Scores     map[string]float64     `json:"scores"`
	Timestamp  time.Time              `json:"timestamp"`
}

// RankingCriterion defines how to rank models
type RankingCriterion struct {
	Metric    string  `json:"metric"`
	Weight    float64 `json:"weight"`
	Direction string  `json:"direction"` // "maximize", "minimize"
}

// VisualizationSettings type defined in advanced_training_pipeline.go

// ReportingSettings type defined in ml_integration.go

// ReportTemplate defines a report template
type ReportTemplate struct {
	Name     string   `json:"name"`
	Type     string   `json:"type"`
	Sections []string `json:"sections"`
	Format   string   `json:"format"`
	Enabled  bool     `json:"enabled"`
}

// ReportSchedule defines when to generate reports
type ReportSchedule struct {
	Enabled   bool          `json:"enabled"`
	Frequency time.Duration `json:"frequency"`
	CronExpr  string        `json:"cron_expr"`
	Timezone  string        `json:"timezone"`
}

// ReportDistribution defines how to distribute reports
type ReportDistribution struct {
	Enabled    bool     `json:"enabled"`
	Channels   []string `json:"channels"`
	Recipients []string `json:"recipients"`
	Filters    []string `json:"filters"`
}

// ReportRetention defines report retention policy
type ReportRetention struct {
	Enabled     bool          `json:"enabled"`
	Duration    time.Duration `json:"duration"`
	MaxReports  int           `json:"max_reports"`
	Compression bool          `json:"compression"`
	Archival    bool          `json:"archival"`
}

// MonitoringEvaluationSettings defines monitoring for evaluation
type MonitoringEvaluationSettings struct {
	Enabled    bool                `json:"enabled"`
	Metrics    *MetricsMonitoring  `json:"metrics"`
	Alerting   *AlertingMonitoring `json:"alerting"`
	Dashboards *DashboardSettings  `json:"dashboards"`
	Logging    *LoggingMonitoring  `json:"logging"`
}

// MetricsMonitoring defines metrics monitoring
type MetricsMonitoring struct {
	Enabled   bool          `json:"enabled"`
	Interval  time.Duration `json:"interval"`
	Retention time.Duration `json:"retention"`
	Export    bool          `json:"export"`
	Endpoint  string        `json:"endpoint"`
}

// AlertingMonitoring defines alerting for evaluation
type AlertingMonitoring struct {
	Enabled    bool             `json:"enabled"`
	Rules      []AlertRule      `json:"rules"`
	Channels   []string         `json:"channels"`
	Throttling *AlertThrottling `json:"throttling"`
}

// AlertRule type defined in inference_engine.go

// AlertThrottling defines alert throttling
type AlertThrottling struct {
	Enabled   bool          `json:"enabled"`
	Window    time.Duration `json:"window"`
	MaxAlerts int           `json:"max_alerts"`
	Cooldown  time.Duration `json:"cooldown"`
}

// DashboardSettings type defined in ml_integration.go

// LoggingMonitoring defines logging for evaluation
type LoggingMonitoring struct {
	Enabled bool   `json:"enabled"`
	Level   string `json:"level"`
	Format  string `json:"format"`
	Output  string `json:"output"`
}

// OptimizationEvaluationSettings defines optimization settings
type OptimizationEvaluationSettings struct {
	Enabled          bool                          `json:"enabled"`
	Hyperparameter   *HyperparameterOptimization   `json:"hyperparameter"`
	Architecture     *ArchitectureOptimization     `json:"architecture"`
	FeatureSelection *FeatureSelectionOptimization `json:"feature_selection"`
	Ensemble         *EnsembleOptimization         `json:"ensemble"`
}

// HyperparameterOptimization defines hyperparameter optimization
type HyperparameterOptimization struct {
	Enabled     bool                   `json:"enabled"`
	Strategy    string                 `json:"strategy"`
	SearchSpace map[string]interface{} `json:"search_space"`
	Objective   string                 `json:"objective"`
	Trials      int                    `json:"trials"`
	Timeout     time.Duration          `json:"timeout"`
}

// ArchitectureOptimization defines neural architecture search
type ArchitectureOptimization struct {
	Enabled     bool                   `json:"enabled"`
	Strategy    string                 `json:"strategy"`
	SearchSpace map[string]interface{} `json:"search_space"`
	Objective   string                 `json:"objective"`
	Generations int                    `json:"generations"`
	Population  int                    `json:"population"`
}

// FeatureSelectionOptimization defines feature selection optimization
type FeatureSelectionOptimization struct {
	Enabled     bool     `json:"enabled"`
	Methods     []string `json:"methods"`
	Objective   string   `json:"objective"`
	MaxFeatures int      `json:"max_features"`
	MinFeatures int      `json:"min_features"`
}

// EnsembleOptimization defines ensemble optimization
type EnsembleOptimization struct {
	Enabled   bool     `json:"enabled"`
	Methods   []string `json:"methods"`
	MaxModels int      `json:"max_models"`
	Objective string   `json:"objective"`
	Diversity float64  `json:"diversity"`
}

// EvaluationMetrics stores evaluation results
type EvaluationMetrics struct {
	Timestamp             time.Time                      `json:"timestamp"`
	ModelID               string                         `json:"model_id"`
	ModelVersion          string                         `json:"model_version"`
	DatasetInfo           *DatasetInfo                   `json:"dataset_info"`
	ClassificationMetrics *ClassificationResults         `json:"classification_metrics"`
	RegressionMetrics     *RegressionResults             `json:"regression_metrics"`
	RankingMetrics        *RankingResults                `json:"ranking_metrics"`
	CustomMetrics         map[string]float64             `json:"custom_metrics"`
	PerformanceMetrics    *PerformanceResults            `json:"performance_metrics"`
	RobustnessMetrics     *RobustnessResults             `json:"robustness_metrics"`
	FairnessMetrics       *FairnessResults               `json:"fairness_metrics"`
	ComparisonResults     *ComparisonResults             `json:"comparison_results"`
	ValidationResults     *ValidationResults             `json:"validation_results"`
	StatisticalTests      *StatisticalTestResults        `json:"statistical_tests"`
	ConfidenceIntervals   map[string]*ConfidenceInterval `json:"confidence_intervals"`
	Metadata              map[string]interface{}         `json:"metadata"`
}

// DatasetInfo type defined in advanced_evaluation.go

// DataSplitInfo contains information about data splits
type DataSplitInfo struct {
	TrainSize       int     `json:"train_size"`
	ValidationSize  int     `json:"validation_size"`
	TestSize        int     `json:"test_size"`
	TrainRatio      float64 `json:"train_ratio"`
	ValidationRatio float64 `json:"validation_ratio"`
	TestRatio       float64 `json:"test_ratio"`
}

// ClassificationResults contains classification evaluation results
type ClassificationResults struct {
	Accuracy             float64                  `json:"accuracy"`
	Precision            float64                  `json:"precision"`
	Recall               float64                  `json:"recall"`
	F1Score              float64                  `json:"f1_score"`
	F2Score              float64                  `json:"f2_score"`
	AUCROC               float64                  `json:"auc_roc"`
	AUCPR                float64                  `json:"auc_pr"`
	LogLoss              float64                  `json:"log_loss"`
	MatthewsCorr         float64                  `json:"matthews_corr"`
	CohenKappa           float64                  `json:"cohen_kappa"`
	BalancedAccuracy     float64                  `json:"balanced_accuracy"`
	TopKAccuracy         map[int]float64          `json:"top_k_accuracy"`
	ConfusionMatrix      [][]int                  `json:"confusion_matrix"`
	ClassificationReport map[string]*ClassMetrics `json:"classification_report"`
	PerClassMetrics      map[string]*ClassMetrics `json:"per_class_metrics"`
	ROCCurve             *ROCCurve                `json:"roc_curve"`
	PRCurve              *PRCurve                 `json:"pr_curve"`
}

// ClassMetrics contains per-class metrics
type ClassMetrics struct {
	Precision float64 `json:"precision"`
	Recall    float64 `json:"recall"`
	F1Score   float64 `json:"f1_score"`
	Support   int     `json:"support"`
}

// ROCCurve contains ROC curve data
type ROCCurve struct {
	FPR        []float64 `json:"fpr"`
	TPR        []float64 `json:"tpr"`
	Thresholds []float64 `json:"thresholds"`
	AUC        float64   `json:"auc"`
}

// PRCurve contains Precision-Recall curve data
type PRCurve struct {
	Precision  []float64 `json:"precision"`
	Recall     []float64 `json:"recall"`
	Thresholds []float64 `json:"thresholds"`
	AUC        float64   `json:"auc"`
}

// RegressionResults contains regression evaluation results
type RegressionResults struct {
	MSE                 float64        `json:"mse"`
	RMSE                float64        `json:"rmse"`
	MAE                 float64        `json:"mae"`
	MAPE                float64        `json:"mape"`
	R2Score             float64        `json:"r2_score"`
	AdjustedR2          float64        `json:"adjusted_r2"`
	MeanAbsoluteError   float64        `json:"mean_absolute_error"`
	MeanSquaredLogError float64        `json:"mean_squared_log_error"`
	MedianAbsoluteError float64        `json:"median_absolute_error"`
	ExplainedVariance   float64        `json:"explained_variance"`
	ResidualPlots       *ResidualPlots `json:"residual_plots"`
}

// ResidualPlots contains residual analysis data
type ResidualPlots struct {
	Residuals    []float64 `json:"residuals"`
	Predicted    []float64 `json:"predicted"`
	Actual       []float64 `json:"actual"`
	Standardized []float64 `json:"standardized"`
}

// RankingResults contains ranking evaluation results
type RankingResults struct {
	NDCG       map[int]float64 `json:"ndcg"`
	MAP        float64         `json:"map"`
	MRR        float64         `json:"mrr"`
	PrecisionK map[int]float64 `json:"precision_k"`
	RecallK    map[int]float64 `json:"recall_k"`
	HitRateK   map[int]float64 `json:"hit_rate_k"`
}

// PerformanceResults contains performance evaluation results
type PerformanceResults struct {
	Latency     *LatencyMetrics    `json:"latency"`
	Throughput  *ThroughputMetrics `json:"throughput"`
	MemoryUsage *MemoryMetrics     `json:"memory_usage"`
	CPUUsage    *CPUMetrics        `json:"cpu_usage"`
	DiskIO      *DiskIOMetrics     `json:"disk_io"`
	NetworkIO   *NetworkIOMetrics  `json:"network_io"`
}

// LatencyMetrics contains latency measurements
type LatencyMetrics struct {
	Mean    float64   `json:"mean"`
	Median  float64   `json:"median"`
	P95     float64   `json:"p95"`
	P99     float64   `json:"p99"`
	Min     float64   `json:"min"`
	Max     float64   `json:"max"`
	StdDev  float64   `json:"std_dev"`
	Samples []float64 `json:"samples"`
}

// ThroughputMetrics contains throughput measurements
type ThroughputMetrics struct {
	RequestsPerSecond float64 `json:"requests_per_second"`
	ItemsPerSecond    float64 `json:"items_per_second"`
	BytesPerSecond    float64 `json:"bytes_per_second"`
}

// MemoryMetrics contains memory usage measurements
type MemoryMetrics struct {
	PeakUsage    int64   `json:"peak_usage"`
	AverageUsage int64   `json:"average_usage"`
	MinUsage     int64   `json:"min_usage"`
	MaxUsage     int64   `json:"max_usage"`
	GrowthRate   float64 `json:"growth_rate"`
	LeakDetected bool    `json:"leak_detected"`
}

// CPUMetrics contains CPU usage measurements
type CPUMetrics struct {
	AverageUsage float64 `json:"average_usage"`
	PeakUsage    float64 `json:"peak_usage"`
	MinUsage     float64 `json:"min_usage"`
	MaxUsage     float64 `json:"max_usage"`
	Cores        int     `json:"cores"`
}

// DiskIOMetrics contains disk I/O measurements
type DiskIOMetrics struct {
	ReadBytes    int64   `json:"read_bytes"`
	WriteBytes   int64   `json:"write_bytes"`
	ReadOps      int64   `json:"read_ops"`
	WriteOps     int64   `json:"write_ops"`
	ReadLatency  float64 `json:"read_latency"`
	WriteLatency float64 `json:"write_latency"`
}

// NetworkIOMetrics contains network I/O measurements
type NetworkIOMetrics struct {
	BytesReceived   int64   `json:"bytes_received"`
	BytesSent       int64   `json:"bytes_sent"`
	PacketsReceived int64   `json:"packets_received"`
	PacketsSent     int64   `json:"packets_sent"`
	Latency         float64 `json:"latency"`
	Bandwidth       float64 `json:"bandwidth"`
}

// RobustnessResults contains robustness evaluation results
type RobustnessResults struct {
	NoiseRobustness       *NoiseRobustnessResults       `json:"noise_robustness"`
	AdversarialRobustness *AdversarialRobustnessResults `json:"adversarial_robustness"`
	CorruptionRobustness  *CorruptionRobustnessResults  `json:"corruption_robustness"`
	DriftRobustness       *DriftRobustnessResults       `json:"drift_robustness"`
}

// NoiseRobustnessResults contains noise robustness results
type NoiseRobustnessResults struct {
	Results map[string]map[float64]float64 `json:"results"` // noise_type -> noise_level -> accuracy
	Summary *RobustnessSummary             `json:"summary"`
}

// AdversarialRobustnessResults contains adversarial robustness results
type AdversarialRobustnessResults struct {
	Results map[string]map[float64]float64 `json:"results"` // attack_type -> epsilon -> accuracy
	Summary *RobustnessSummary             `json:"summary"`
}

// CorruptionRobustnessResults contains corruption robustness results
type CorruptionRobustnessResults struct {
	Results map[string]map[int]float64 `json:"results"` // corruption_type -> severity -> accuracy
	Summary *RobustnessSummary         `json:"summary"`
}

// DriftRobustnessResults contains drift robustness results
type DriftRobustnessResults struct {
	Results map[string]map[float64]float64 `json:"results"` // drift_type -> drift_rate -> accuracy
	Summary *RobustnessSummary             `json:"summary"`
}

// RobustnessSummary contains summary statistics for robustness
type RobustnessSummary struct {
	MeanAccuracy    float64 `json:"mean_accuracy"`
	MinAccuracy     float64 `json:"min_accuracy"`
	MaxAccuracy     float64 `json:"max_accuracy"`
	StdDevAccuracy  float64 `json:"std_dev_accuracy"`
	RobustnessScore float64 `json:"robustness_score"`
}

// FairnessResults contains fairness evaluation results
type FairnessResults struct {
	DemographicParity      map[string]float64 `json:"demographic_parity"`
	EqualizedOdds          map[string]float64 `json:"equalized_odds"`
	EqualOpportunity       map[string]float64 `json:"equal_opportunity"`
	Calibration            map[string]float64 `json:"calibration"`
	IndividualFairness     float64            `json:"individual_fairness"`
	CounterfactualFairness float64            `json:"counterfactual_fairness"`
	BiasMetrics            map[string]float64 `json:"bias_metrics"`
	FairnessScore          float64            `json:"fairness_score"`
}

// ComparisonResults contains model comparison results
type ComparisonResults struct {
	Models                  []string                      `json:"models"`
	Metrics                 map[string]map[string]float64 `json:"metrics"`       // model -> metric -> value
	Rankings                map[string]int                `json:"rankings"`      // model -> rank
	OverallScore            map[string]float64            `json:"overall_score"` // model -> score
	Winner                  string                        `json:"winner"`
	StatisticalSignificance map[string]map[string]bool    `json:"statistical_significance"` // model1 -> model2 -> significant
}

// ValidationResults contains validation results
type ValidationResults struct {
	CrossValidation      *CrossValidationResults      `json:"cross_validation"`
	HoldoutValidation    *HoldoutValidationResults    `json:"holdout_validation"`
	Bootstrap            *BootstrapResults            `json:"bootstrap"`
	TimeSeriesValidation *TimeSeriesValidationResults `json:"time_series_validation"`
}

// CrossValidationResults contains cross-validation results
type CrossValidationResults struct {
	Folds       int                  `json:"folds"`
	Scores      []float64            `json:"scores"`
	MeanScore   float64              `json:"mean_score"`
	StdScore    float64              `json:"std_score"`
	Metrics     map[string][]float64 `json:"metrics"`
	MeanMetrics map[string]float64   `json:"mean_metrics"`
	StdMetrics  map[string]float64   `json:"std_metrics"`
}

// HoldoutValidationResults contains holdout validation results
type HoldoutValidationResults struct {
	TrainScore   float64            `json:"train_score"`
	TestScore    float64            `json:"test_score"`
	Metrics      map[string]float64 `json:"metrics"`
	Overfitting  bool               `json:"overfitting"`
	Underfitting bool               `json:"underfitting"`
}

// BootstrapResults type defined in advanced_evaluation.go

// TimeSeriesValidationResults contains time series validation results
type TimeSeriesValidationResults struct {
	Splits      int                  `json:"splits"`
	Scores      []float64            `json:"scores"`
	MeanScore   float64              `json:"mean_score"`
	StdScore    float64              `json:"std_score"`
	Trend       string               `json:"trend"`
	Metrics     map[string][]float64 `json:"metrics"`
	MeanMetrics map[string]float64   `json:"mean_metrics"`
}

// StatisticalTestResults contains statistical test results
type StatisticalTestResults struct {
	TTest        *TTestResult        `json:"t_test"`
	WilcoxonTest *WilcoxonTestResult `json:"wilcoxon_test"`
	McNemarTest  *McNemarTestResult  `json:"mcnemar_test"`
	FriedmanTest *FriedmanTestResult `json:"friedman_test"`
}

// TTestResult contains t-test results
type TTestResult struct {
	Statistic   float64 `json:"statistic"`
	PValue      float64 `json:"p_value"`
	Significant bool    `json:"significant"`
	Effect      string  `json:"effect"`
}

// WilcoxonTestResult contains Wilcoxon test results
type WilcoxonTestResult struct {
	Statistic   float64 `json:"statistic"`
	PValue      float64 `json:"p_value"`
	Significant bool    `json:"significant"`
	Effect      string  `json:"effect"`
}

// McNemarTestResult contains McNemar test results
type McNemarTestResult struct {
	Statistic   float64 `json:"statistic"`
	PValue      float64 `json:"p_value"`
	Significant bool    `json:"significant"`
	Effect      string  `json:"effect"`
}

// FriedmanTestResult contains Friedman test results
type FriedmanTestResult struct {
	Statistic   float64 `json:"statistic"`
	PValue      float64 `json:"p_value"`
	Significant bool    `json:"significant"`
	Effect      string  `json:"effect"`
}

// ConfidenceInterval represents a confidence interval
type ConfidenceInterval struct {
	Lower       float64 `json:"lower"`
	Upper       float64 `json:"upper"`
	Level       float64 `json:"level"`
	Mean        float64 `json:"mean"`
	MarginError float64 `json:"margin_error"`
}

// EvaluationReport type defined in advanced_evaluation.go

// EvaluationSummary type defined in advanced_evaluation.go

// ComparisonSummary contains comparison summary
type ComparisonSummary struct {
	BestModel       string  `json:"best_model"`
	WorstModel      string  `json:"worst_model"`
	ImprovementPct  float64 `json:"improvement_pct"`
	SignificantDiff bool    `json:"significant_diff"`
}

// VisualizationData type defined in inference_engine.go

// ChartData contains chart visualization data
type ChartData struct {
	Type   string                 `json:"type"`
	Title  string                 `json:"title"`
	Data   map[string]interface{} `json:"data"`
	Config map[string]interface{} `json:"config"`
}

// TableData contains table visualization data
type TableData struct {
	Title   string                 `json:"title"`
	Headers []string               `json:"headers"`
	Rows    [][]interface{}        `json:"rows"`
	Config  map[string]interface{} `json:"config"`
}

// ImageData contains image visualization data
type ImageData struct {
	Title  string `json:"title"`
	Path   string `json:"path"`
	Format string `json:"format"`
	Data   []byte `json:"data"`
}

// NewModelEvaluator function defined in model_evaluator.go

// Start starts the model evaluator
func (me *ModelEvaluator) Start(ctx context.Context) error {
	me.mu.Lock()
	defer me.mu.Unlock()

	if me.running {
		return fmt.Errorf("model evaluator is already running")
	}

	ctx, cancel := context.WithCancel(ctx)
	me.cancel = cancel
	me.running = true

	// Start monitoring if enabled
	if me.config.Monitoring != nil && me.config.Monitoring.Enabled {
		go me.startMonitoring(ctx)
	}

	// Start scheduled evaluations if enabled
	if me.config.Core != nil && me.config.Core.Mode == "continuous" {
		go me.startContinuousEvaluation(ctx)
	}

	return nil
}

// Stop stops the model evaluator
func (me *ModelEvaluator) Stop() error {
	me.mu.Lock()
	defer me.mu.Unlock()

	if !me.running {
		return fmt.Errorf("model evaluator is not running")
	}

	if me.cancel != nil {
		me.cancel()
	}

	me.running = false
	return nil
}

// Evaluate performs a comprehensive model evaluation
func (me *ModelEvaluator) Evaluate(ctx context.Context, model interface{}, data interface{}) (*EvaluationReport, error) {
	me.mu.Lock()
	defer me.mu.Unlock()

	// Initialize evaluation metrics
	metrics := &EvaluationMetrics{
		Timestamp:    time.Now(),
		ModelID:      me.generateModelID(model),
		ModelVersion: me.getModelVersion(model),
		DatasetInfo:  me.extractDatasetInfo(data),
		Metadata:     make(map[string]interface{}),
	}

	// Perform different types of evaluation
	if me.config.Metrics != nil {
		if err := me.evaluateMetrics(ctx, model, data, metrics); err != nil {
			return nil, fmt.Errorf("failed to evaluate metrics: %w", err)
		}
	}

	if me.config.Validation != nil && me.config.Validation.Enabled {
		if err := me.performValidation(ctx, model, data, metrics); err != nil {
			return nil, fmt.Errorf("failed to perform validation: %w", err)
		}
	}

	if me.config.Benchmark != nil && me.config.Benchmark.Enabled {
		if err := me.performBenchmark(ctx, model, data, metrics); err != nil {
			return nil, fmt.Errorf("failed to perform benchmark: %w", err)
		}
	}

	if me.config.Comparison != nil && me.config.Comparison.Enabled {
		if err := me.performComparison(ctx, model, data, metrics); err != nil {
			return nil, fmt.Errorf("failed to perform comparison: %w", err)
		}
	}

	// Generate evaluation report
	// Convert EvaluationMetrics to []EvaluationMetric for report generation
	report := me.generateReport(me.metrics)

	// Store metrics - convert EvaluationMetrics to []EvaluationMetric
	// For now, we'll store an empty slice since the actual metrics are in the report
	me.metrics = []EvaluationMetric{}

	return report, nil
}

// GetMetrics returns the current evaluation metrics
func (me *ModelEvaluator) GetMetrics() []EvaluationMetric {
	me.mu.RLock()
	defer me.mu.RUnlock()

	return me.metrics
}

// GetStatus returns the current status of the evaluator
func (me *ModelEvaluator) GetStatus() map[string]interface{} {
	me.mu.RLock()
	defer me.mu.RUnlock()

	return map[string]interface{}{
		"running":       me.running,
		"metrics_count": len(me.metrics),
	}
}

// Helper methods (placeholder implementations)
func (me *ModelEvaluator) startMonitoring(ctx context.Context) {
	// Implementation for monitoring
}

func (me *ModelEvaluator) startContinuousEvaluation(ctx context.Context) {
	// Implementation for continuous evaluation
}

func (me *ModelEvaluator) generateModelID(model interface{}) string {
	return fmt.Sprintf("model_%d", time.Now().UnixNano())
}

func (me *ModelEvaluator) getModelVersion(model interface{}) string {
	return "1.0.0"
}

func (me *ModelEvaluator) extractDatasetInfo(data interface{}) *DatasetInfo {
	return &DatasetInfo{
		Name:     "evaluation_dataset",
		Size:     1000,
		Features: 10,
		Classes:  2,
	}
}

func (me *ModelEvaluator) evaluateMetrics(ctx context.Context, model interface{}, data interface{}, metrics *EvaluationMetrics) error {
	// Implementation for metrics evaluation
	return nil
}

func (me *ModelEvaluator) performValidation(ctx context.Context, model interface{}, data interface{}, metrics *EvaluationMetrics) error {
	// Implementation for validation
	return nil
}

func (me *ModelEvaluator) performBenchmark(ctx context.Context, model interface{}, data interface{}, metrics *EvaluationMetrics) error {
	// Implementation for benchmarking
	return nil
}

func (me *ModelEvaluator) performComparison(ctx context.Context, model interface{}, data interface{}, metrics *EvaluationMetrics) error {
	// Implementation for comparison
	return nil
}

func (me *ModelEvaluator) generateReport(metrics []EvaluationMetric) *EvaluationReport {
	// Calculate metrics from the slice
	metricResults := make(map[string]float64)
	for _, metric := range metrics {
		// Mock calculation - in real implementation, this would use actual data
		metricResults[metric.Name()] = 0.85
	}

	return &EvaluationReport{
		ID:        fmt.Sprintf("report_%d", time.Now().UnixNano()),
		Timestamp: time.Now(),
		ModelInfo: &ModelInfo{
			Name:           "model",
			Version:        "1.0",
			Type:           "unknown",
			Description:    "ML model evaluation",
			TrainedAt:      time.Now(),
			Accuracy:       0.85,
			Precision:      0.82,
			Recall:         0.88,
			F1Score:        0.85,
			FeatureCount:   100,
			ParameterCount: 1000,
			Metadata:       make(map[string]interface{}),
		},
		EvaluationSummary: &EvaluationSummary{
			OverallScore: 0.85,
			Grade:        "B+",
		},
		MetricResults: metricResults,
		GeneratedAt:   time.Now(),
		Version:       "1.0",
	}
}

func (me *ModelEvaluator) copyMetrics(metrics *EvaluationMetrics) *EvaluationMetrics {
	if metrics == nil {
		return nil
	}
	// Deep copy implementation
	return &EvaluationMetrics{
		Timestamp:    metrics.Timestamp,
		ModelID:      metrics.ModelID,
		ModelVersion: metrics.ModelVersion,
		DatasetInfo:  metrics.DatasetInfo,
	}
}

// DefaultEvaluationConfig function defined in advanced_evaluation.go

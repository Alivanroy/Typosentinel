# ML Models Directory

This directory contains trained machine learning models used by TypoSentinel for threat detection and analysis.

## Model Types

- **Threat Detection Models**: Models trained to identify malicious packages
- **Typosquatting Detection**: Models for detecting typosquatting attempts
- **Behavioral Analysis**: Models for analyzing package behavior patterns

## Supported Formats

- `.pkl` - Pickle files for scikit-learn models
- `.joblib` - Joblib serialized models
- `.h5` - Keras/TensorFlow models
- `.onnx` - ONNX format for cross-platform compatibility

## Model Loading

Models are automatically loaded by the ML service based on configuration:

```yaml
ml:
  enabled: true
  model_path: "./ml/models/"
```

## Model Management

- Models can be retrained via the API: `POST /api/v1/ml/models/train`
- Model status can be checked via: `GET /api/v1/ml/models/status`
- Models are versioned and can be rolled back if needed

## Security

- Models are validated for integrity before loading
- Only authorized users can trigger model retraining
- Model files are excluded from version control for security
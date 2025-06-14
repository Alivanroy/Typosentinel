#!/usr/bin/env python3
"""
ML API Server for TypoSentinel

This module provides a REST API server for the ML models,
allowing the Go backend to interact with Python ML components.
"""

import os
import sys
import logging
import asyncio
from typing import List, Dict, Any, Optional
from datetime import datetime
import json
from dataclasses import asdict

# Add the parent directory to the path to import our models
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi import FastAPI, HTTPException, Depends, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel, Field
import uvicorn

from models.semantic_similarity import SemanticSimilarityModel, PackageFeatures as SimilarityPackageFeatures
from models.malicious_classifier import MaliciousPackageClassifier, PackageFeatures as ClassifierPackageFeatures

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Security
security = HTTPBearer(auto_error=False)

# Pydantic models for API
class PackageInfo(BaseModel):
    name: str
    registry: str
    version: str = ""
    description: str = ""
    author: str = ""
    downloads: int = 0
    creation_date: str = ""
    last_updated: str = ""
    dependencies: List[str] = Field(default_factory=list)
    keywords: List[str] = Field(default_factory=list)
    license: str = ""
    homepage: str = ""
    repository: str = ""
    size: int = 0

class SimilarityRequest(BaseModel):
    package_name: str
    registry: str = "npm"
    top_k: int = 10
    threshold: float = 0.7
    exclude: List[str] = Field(default_factory=list)

class SimilarityResult(BaseModel):
    package_name: str
    registry: str
    score: float
    distance: float
    rank: int

class SimilarityResponse(BaseModel):
    results: List[SimilarityResult]
    model: str
    time_ms: float

class MaliciousRequest(BaseModel):
    package_name: str
    registry: str = "npm"
    version: str = ""
    features: Optional[Dict[str, Any]] = None

class MaliciousResponse(BaseModel):
    is_malicious: bool
    score: float
    confidence: float
    reasons: List[str]
    features: Dict[str, Any]
    model: str
    time_ms: float

class BatchAnalysisRequest(BaseModel):
    packages: List[PackageInfo]
    options: Dict[str, Any] = Field(default_factory=dict)

class PackageAnalysisResult(BaseModel):
    package: PackageInfo
    similarities: Optional[List[SimilarityResult]] = None
    malicious_check: Optional[MaliciousResponse] = None
    threats: List[Dict[str, Any]] = Field(default_factory=list)
    errors: List[str] = Field(default_factory=list)

class BatchAnalysisResponse(BaseModel):
    results: List[PackageAnalysisResult]
    time_ms: float

class ModelInfo(BaseModel):
    name: str
    version: str
    description: str
    type: str
    trained_at: Optional[str] = None
    accuracy: Optional[float] = None
    precision: Optional[float] = None
    recall: Optional[float] = None
    f1_score: Optional[float] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

class HealthResponse(BaseModel):
    status: str
    timestamp: str
    models: Dict[str, bool]
    version: str

# Global model instances
similarity_model: Optional[SemanticSimilarityModel] = None
malicious_classifier: Optional[MaliciousPackageClassifier] = None

# API configuration
API_KEY = os.getenv("TYPOSENTINEL_API_KEY", "dev-key-123")
API_VERSION = "1.0.0"

# Initialize FastAPI app
app = FastAPI(
    title="TypoSentinel ML API",
    description="Machine Learning API for TypoSentinel package security analysis",
    version=API_VERSION,
    docs_url="/docs",
    redoc_url="/redoc"
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Authentication dependency
async def verify_api_key(credentials: HTTPAuthorizationCredentials = Depends(security)):
    if not credentials:
        raise HTTPException(status_code=401, detail="API key required")
    
    if credentials.credentials != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid API key")
    
    return credentials.credentials

# Startup event
@app.on_event("startup")
async def startup_event():
    """Initialize ML models on startup."""
    global similarity_model, malicious_classifier
    
    logger.info("Starting TypoSentinel ML API Server...")
    
    try:
        # Initialize similarity model
        logger.info("Loading semantic similarity model...")
        similarity_model = SemanticSimilarityModel()
        
        # Initialize malicious classifier
        logger.info("Loading malicious package classifier...")
        malicious_classifier = MaliciousPackageClassifier()
        
        logger.info("All models loaded successfully")
        
    except Exception as e:
        logger.error(f"Failed to load models: {e}")
        raise

# Shutdown event
@app.on_event("shutdown")
async def shutdown_event():
    """Cleanup on shutdown."""
    logger.info("Shutting down TypoSentinel ML API Server...")

# Health check endpoint
@app.get("/health", response_model=HealthResponse)
async def health_check():
    """Health check endpoint."""
    return HealthResponse(
        status="healthy",
        timestamp=datetime.now().isoformat(),
        models={
            "similarity_model": similarity_model is not None,
            "malicious_classifier": malicious_classifier is not None and malicious_classifier.is_trained
        },
        version=API_VERSION
    )

# Model information endpoints
@app.get("/models", response_model=List[ModelInfo])
async def get_models(api_key: str = Depends(verify_api_key)):
    """Get information about available models."""
    models = []
    
    if similarity_model:
        stats = similarity_model.get_stats()
        models.append(ModelInfo(
            name="semantic_similarity",
            version="1.0.0",
            description="Semantic similarity model using sentence transformers",
            type="similarity",
            metadata=stats
        ))
    
    if malicious_classifier:
        stats = malicious_classifier.get_model_stats()
        models.append(ModelInfo(
            name="malicious_classifier",
            version="1.0.0",
            description="Multi-modal malicious package classifier",
            type="classification",
            metadata=stats
        ))
    
    return models

@app.get("/models/{model_name}", response_model=ModelInfo)
async def get_model_info(model_name: str, api_key: str = Depends(verify_api_key)):
    """Get information about a specific model."""
    if model_name == "semantic_similarity" and similarity_model:
        stats = similarity_model.get_stats()
        return ModelInfo(
            name="semantic_similarity",
            version="1.0.0",
            description="Semantic similarity model using sentence transformers",
            type="similarity",
            metadata=stats
        )
    elif model_name == "malicious_classifier" and malicious_classifier:
        stats = malicious_classifier.get_model_stats()
        return ModelInfo(
            name="malicious_classifier",
            version="1.0.0",
            description="Multi-modal malicious package classifier",
            type="classification",
            metadata=stats
        )
    else:
        raise HTTPException(status_code=404, detail="Model not found")

# Similarity endpoints
@app.post("/similarity", response_model=SimilarityResponse)
async def find_similar_packages(request: SimilarityRequest, api_key: str = Depends(verify_api_key)):
    """Find packages similar to the given package name."""
    if not similarity_model:
        raise HTTPException(status_code=503, detail="Similarity model not available")
    
    start_time = datetime.now()
    
    try:
        # Find similar packages
        similar_packages = similarity_model.find_similar(
            package_name=request.package_name,
            top_k=request.top_k,
            threshold=request.threshold,
            exclude_exact=True
        )
        
        # Convert results
        results = []
        for i, (name, score) in enumerate(similar_packages):
            if name not in request.exclude:
                results.append(SimilarityResult(
                    package_name=name,
                    registry=request.registry,  # Assume same registry for now
                    score=score,
                    distance=1.0 - score,
                    rank=i + 1
                ))
        
        end_time = datetime.now()
        time_ms = (end_time - start_time).total_seconds() * 1000
        
        return SimilarityResponse(
            results=results,
            model="semantic_similarity",
            time_ms=time_ms
        )
        
    except Exception as e:
        logger.error(f"Error in similarity search: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Malicious detection endpoints
@app.post("/malicious", response_model=MaliciousResponse)
async def check_malicious_package(request: MaliciousRequest, api_key: str = Depends(verify_api_key)):
    """Check if a package is malicious."""
    if not malicious_classifier:
        raise HTTPException(status_code=503, detail="Malicious classifier not available")
    
    if not malicious_classifier.is_trained:
        raise HTTPException(status_code=503, detail="Malicious classifier not trained")
    
    start_time = datetime.now()
    
    try:
        # Create package features
        package_features = ClassifierPackageFeatures(
            name=request.package_name,
            registry=request.registry,
            version=request.version
        )
        
        # If additional features are provided, update the package
        if request.features:
            for key, value in request.features.items():
                if hasattr(package_features, key):
                    setattr(package_features, key, value)
        
        # Predict
        result = malicious_classifier.predict(package_features)
        
        end_time = datetime.now()
        time_ms = (end_time - start_time).total_seconds() * 1000
        
        return MaliciousResponse(
            is_malicious=result['is_malicious'],
            score=result['score'],
            confidence=result['confidence'],
            reasons=result['reasons'],
            features=result['features'],
            model="malicious_classifier",
            time_ms=time_ms
        )
        
    except Exception as e:
        logger.error(f"Error in malicious detection: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Batch analysis endpoint
@app.post("/batch", response_model=BatchAnalysisResponse)
async def batch_analyze_packages(request: BatchAnalysisRequest, 
                               background_tasks: BackgroundTasks,
                               api_key: str = Depends(verify_api_key)):
    """Perform batch analysis of multiple packages."""
    start_time = datetime.now()
    
    try:
        results = []
        
        for package_info in request.packages:
            result = PackageAnalysisResult(
                package=package_info,
                similarities=[],
                malicious_check=None,
                threats=[],
                errors=[]
            )
            
            try:
                # Check similarity if requested
                if request.options.get('check_similarity', True) and similarity_model:
                    similarity_threshold = request.options.get('similarity_threshold', 0.8)
                    top_k = request.options.get('top_k', 10)
                    
                    similar_packages = similarity_model.find_similar(
                        package_name=package_info.name,
                        top_k=top_k,
                        threshold=similarity_threshold
                    )
                    
                    result.similarities = [
                        SimilarityResult(
                            package_name=name,
                            registry=package_info.registry,
                            score=score,
                            distance=1.0 - score,
                            rank=i + 1
                        )
                        for i, (name, score) in enumerate(similar_packages)
                    ]
                
                # Check malicious if requested
                if request.options.get('check_malicious', True) and malicious_classifier and malicious_classifier.is_trained:
                    package_features = ClassifierPackageFeatures(
                        name=package_info.name,
                        registry=package_info.registry,
                        version=package_info.version,
                        description=package_info.description,
                        author=package_info.author,
                        downloads=package_info.downloads,
                        creation_date=package_info.creation_date,
                        last_updated=package_info.last_updated,
                        dependencies=package_info.dependencies,
                        keywords=package_info.keywords,
                        license=package_info.license,
                        homepage=package_info.homepage,
                        repository=package_info.repository,
                        size=package_info.size
                    )
                    
                    malicious_result = malicious_classifier.predict(package_features)
                    
                    result.malicious_check = MaliciousResponse(
                        is_malicious=malicious_result['is_malicious'],
                        score=malicious_result['score'],
                        confidence=malicious_result['confidence'],
                        reasons=malicious_result['reasons'],
                        features=malicious_result['features'],
                        model="malicious_classifier",
                        time_ms=0  # Will be calculated at the end
                    )
                
                # Generate threats based on analysis
                threats = []
                
                # Add similarity-based threats
                if result.similarities:
                    for sim in result.similarities:
                        if sim.score > 0.85:
                            threats.append({
                                'type': 'typosquatting',
                                'severity': 'high' if sim.score > 0.95 else 'medium',
                                'description': f"Package '{package_info.name}' is similar to '{sim.package_name}' (score: {sim.score:.3f})",
                                'similar_package': sim.package_name,
                                'similarity_score': sim.score
                            })
                
                # Add malicious-based threats
                if result.malicious_check and result.malicious_check.is_malicious:
                    threats.append({
                        'type': 'malicious',
                        'severity': 'critical' if result.malicious_check.score > 0.8 else 'high',
                        'description': f"Package '{package_info.name}' is likely malicious (score: {result.malicious_check.score:.3f})",
                        'malicious_score': result.malicious_check.score,
                        'reasons': result.malicious_check.reasons
                    })
                
                result.threats = threats
                
            except Exception as e:
                logger.error(f"Error analyzing package {package_info.name}: {e}")
                result.errors.append(str(e))
            
            results.append(result)
        
        end_time = datetime.now()
        time_ms = (end_time - start_time).total_seconds() * 1000
        
        return BatchAnalysisResponse(
            results=results,
            time_ms=time_ms
        )
        
    except Exception as e:
        logger.error(f"Error in batch analysis: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Package management endpoints
@app.post("/packages/add")
async def add_packages(packages: List[PackageInfo], 
                      background_tasks: BackgroundTasks,
                      api_key: str = Depends(verify_api_key)):
    """Add packages to the similarity index."""
    if not similarity_model:
        raise HTTPException(status_code=503, detail="Similarity model not available")
    
    try:
        # Convert to similarity package features
        similarity_packages = []
        for pkg in packages:
            similarity_pkg = SimilarityPackageFeatures(
                name=pkg.name,
                registry=pkg.registry,
                version=pkg.version,
                description=pkg.description,
                author=pkg.author,
                downloads=pkg.downloads,
                creation_date=pkg.creation_date,
                last_updated=pkg.last_updated,
                dependencies=pkg.dependencies,
                keywords=pkg.keywords,
                license=pkg.license,
                homepage=pkg.homepage,
                repository=pkg.repository,
                size=pkg.size
            )
            similarity_packages.append(similarity_pkg)
        
        # Add packages in background
        background_tasks.add_task(similarity_model.add_packages, similarity_packages)
        
        return {"message": f"Adding {len(packages)} packages to index", "status": "queued"}
        
    except Exception as e:
        logger.error(f"Error adding packages: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/train")
async def train_classifier(packages: List[PackageInfo], 
                          labels: List[int],
                          background_tasks: BackgroundTasks,
                          api_key: str = Depends(verify_api_key)):
    """Train the malicious classifier."""
    if not malicious_classifier:
        raise HTTPException(status_code=503, detail="Malicious classifier not available")
    
    if len(packages) != len(labels):
        raise HTTPException(status_code=400, detail="Number of packages must match number of labels")
    
    try:
        # Convert to classifier package features
        classifier_packages = []
        for pkg in packages:
            classifier_pkg = ClassifierPackageFeatures(
                name=pkg.name,
                registry=pkg.registry,
                version=pkg.version,
                description=pkg.description,
                author=pkg.author,
                downloads=pkg.downloads,
                creation_date=pkg.creation_date,
                last_updated=pkg.last_updated,
                dependencies=pkg.dependencies,
                keywords=pkg.keywords,
                license=pkg.license,
                homepage=pkg.homepage,
                repository=pkg.repository,
                size=pkg.size
            )
            classifier_packages.append(classifier_pkg)
        
        # Train in background
        background_tasks.add_task(malicious_classifier.train, classifier_packages, labels)
        
        return {"message": f"Training classifier on {len(packages)} packages", "status": "queued"}
        
    except Exception as e:
        logger.error(f"Error training classifier: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Main entry point
if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="TypoSentinel ML API Server")
    parser.add_argument("--host", default="0.0.0.0", help="Host to bind to")
    parser.add_argument("--port", type=int, default=8000, help="Port to bind to")
    parser.add_argument("--workers", type=int, default=1, help="Number of worker processes")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload for development")
    parser.add_argument("--log-level", default="info", help="Log level")
    
    args = parser.parse_args()
    
    uvicorn.run(
        "api_server:app",
        host=args.host,
        port=args.port,
        workers=args.workers,
        reload=args.reload,
        log_level=args.log_level
    )
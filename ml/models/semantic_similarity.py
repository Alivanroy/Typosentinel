#!/usr/bin/env python3
"""
Semantic Similarity Model for TypoSentinel

This module implements semantic similarity detection for package names
using sentence transformers and FAISS for efficient similarity search.
"""

import os
import pickle
import logging
from typing import List, Tuple, Dict, Optional
from dataclasses import dataclass
import numpy as np
from sentence_transformers import SentenceTransformer
import faiss
from sklearn.metrics.pairwise import cosine_similarity

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class PackageFeatures:
    """Store package metadata and features for analysis."""
    name: str
    registry: str
    version: str = ""
    description: str = ""
    author: str = ""
    downloads: int = 0
    creation_date: str = ""
    last_updated: str = ""
    dependencies: List[str] = None
    keywords: List[str] = None
    license: str = ""
    homepage: str = ""
    repository: str = ""
    size: int = 0
    
    def __post_init__(self):
        if self.dependencies is None:
            self.dependencies = []
        if self.keywords is None:
            self.keywords = []

class SemanticSimilarityModel:
    """Semantic similarity model using sentence transformers and FAISS."""
    
    def __init__(self, model_name: str = "sentence-transformers/all-MiniLM-L6-v2", 
                 index_path: str = None, embeddings_path: str = None):
        """
        Initialize the semantic similarity model.
        
        Args:
            model_name: Name of the sentence transformer model
            index_path: Path to save/load FAISS index
            embeddings_path: Path to save/load embeddings
        """
        self.model_name = model_name
        self.index_path = index_path or "models/faiss_index.bin"
        self.embeddings_path = embeddings_path or "models/embeddings.pkl"
        
        # Initialize model
        logger.info(f"Loading sentence transformer model: {model_name}")
        self.model = SentenceTransformer(model_name)
        
        # Initialize FAISS index
        self.dimension = self.model.get_sentence_embedding_dimension()
        self.index = None
        self.package_names = []
        self.package_metadata = {}
        
        # Load existing index if available
        self._load_index()
    
    def _load_index(self) -> bool:
        """Load existing FAISS index and embeddings."""
        try:
            if os.path.exists(self.index_path) and os.path.exists(self.embeddings_path):
                logger.info("Loading existing FAISS index...")
                self.index = faiss.read_index(self.index_path)
                
                with open(self.embeddings_path, 'rb') as f:
                    data = pickle.load(f)
                    self.package_names = data['package_names']
                    self.package_metadata = data['package_metadata']
                
                logger.info(f"Loaded index with {len(self.package_names)} packages")
                return True
        except Exception as e:
            logger.warning(f"Failed to load existing index: {e}")
        
        return False
    
    def _save_index(self):
        """Save FAISS index and embeddings to disk."""
        try:
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(self.index_path), exist_ok=True)
            os.makedirs(os.path.dirname(self.embeddings_path), exist_ok=True)
            
            # Save FAISS index
            faiss.write_index(self.index, self.index_path)
            
            # Save embeddings and metadata
            with open(self.embeddings_path, 'wb') as f:
                pickle.dump({
                    'package_names': self.package_names,
                    'package_metadata': self.package_metadata
                }, f)
            
            logger.info(f"Saved index with {len(self.package_names)} packages")
        except Exception as e:
            logger.error(f"Failed to save index: {e}")
    
    def add_packages(self, packages: List[PackageFeatures]):
        """Add packages to the similarity index."""
        if not packages:
            return
        
        logger.info(f"Adding {len(packages)} packages to index...")
        
        # Extract package names and create embeddings
        new_names = [pkg.name for pkg in packages]
        embeddings = self.model.encode(new_names, convert_to_numpy=True)
        
        # Initialize index if it doesn't exist
        if self.index is None:
            self.index = faiss.IndexFlatIP(self.dimension)  # Inner product for cosine similarity
        
        # Normalize embeddings for cosine similarity
        faiss.normalize_L2(embeddings)
        
        # Add to index
        self.index.add(embeddings.astype(np.float32))
        
        # Update package lists and metadata
        self.package_names.extend(new_names)
        for pkg in packages:
            self.package_metadata[pkg.name] = {
                'registry': pkg.registry,
                'version': pkg.version,
                'description': pkg.description,
                'author': pkg.author,
                'downloads': pkg.downloads,
                'creation_date': pkg.creation_date,
                'last_updated': pkg.last_updated,
                'dependencies': pkg.dependencies,
                'keywords': pkg.keywords,
                'license': pkg.license,
                'homepage': pkg.homepage,
                'repository': pkg.repository,
                'size': pkg.size
            }
        
        # Save updated index
        self._save_index()
        
        logger.info(f"Index now contains {len(self.package_names)} packages")
    
    def find_similar(self, package_name: str, top_k: int = 10, 
                    threshold: float = 0.7, exclude_exact: bool = True) -> List[Tuple[str, float]]:
        """Find similar packages using semantic similarity."""
        if self.index is None or len(self.package_names) == 0:
            logger.warning("No packages in index")
            return []
        
        # Create embedding for query package
        query_embedding = self.model.encode([package_name], convert_to_numpy=True)
        faiss.normalize_L2(query_embedding)
        
        # Search for similar packages
        scores, indices = self.index.search(query_embedding.astype(np.float32), 
                                          min(top_k * 2, len(self.package_names)))
        
        # Process results
        results = []
        for score, idx in zip(scores[0], indices[0]):
            if idx >= len(self.package_names):
                continue
                
            similar_name = self.package_names[idx]
            
            # Skip exact matches if requested
            if exclude_exact and similar_name.lower() == package_name.lower():
                continue
            
            # Apply threshold
            if score >= threshold:
                results.append((similar_name, float(score)))
        
        # Sort by score (descending) and limit results
        results.sort(key=lambda x: x[1], reverse=True)
        return results[:top_k]
    
    def calculate_similarity(self, package1: str, package2: str) -> float:
        """Calculate similarity between two package names."""
        embeddings = self.model.encode([package1, package2], convert_to_numpy=True)
        similarity = cosine_similarity([embeddings[0]], [embeddings[1]])[0][0]
        return float(similarity)
    
    def detect_typosquatting(self, package_name: str, registry: str = "npm", 
                           similarity_threshold: float = 0.8) -> List[Dict]:
        """Detect potential typosquatting attempts."""
        similar_packages = self.find_similar(package_name, top_k=20, 
                                           threshold=similarity_threshold)
        
        threats = []
        for similar_name, score in similar_packages:
            # Get metadata for similar package
            metadata = self.package_metadata.get(similar_name, {})
            
            # Calculate threat severity based on similarity score
            if score >= 0.95:
                severity = "critical"
            elif score >= 0.9:
                severity = "high"
            elif score >= 0.85:
                severity = "medium"
            else:
                severity = "low"
            
            threat = {
                'type': 'typosquatting',
                'package_name': package_name,
                'similar_package': similar_name,
                'similarity_score': score,
                'severity': severity,
                'registry': registry,
                'confidence': score,
                'description': f"Package '{package_name}' is similar to '{similar_name}' (score: {score:.3f})",
                'recommendation': f"Verify if you intended to use '{similar_name}' instead of '{package_name}'",
                'metadata': metadata
            }
            threats.append(threat)
        
        return threats
    
    def batch_similarity_check(self, package_names: List[str], 
                              threshold: float = 0.8) -> Dict[str, List[Tuple[str, float]]]:
        """Perform batch similarity checking for multiple packages."""
        results = {}
        for package_name in package_names:
            results[package_name] = self.find_similar(package_name, threshold=threshold)
        return results
    
    def get_package_embedding(self, package_name: str) -> np.ndarray:
        """Get the embedding vector for a package name."""
        return self.model.encode([package_name], convert_to_numpy=True)[0]
    
    def get_stats(self) -> Dict:
        """Get statistics about the model and index."""
        return {
            'model_name': self.model_name,
            'dimension': self.dimension,
            'total_packages': len(self.package_names),
            'index_size': self.index.ntotal if self.index else 0,
            'registries': list(set(meta.get('registry', 'unknown') 
                                 for meta in self.package_metadata.values()))
        }
    
    def rebuild_index(self, packages: List[PackageFeatures]):
        """Rebuild the entire index from scratch."""
        logger.info("Rebuilding similarity index...")
        
        # Reset index and data
        self.index = None
        self.package_names = []
        self.package_metadata = {}
        
        # Add all packages
        self.add_packages(packages)
        
        logger.info("Index rebuild complete")
    
    def remove_package(self, package_name: str) -> bool:
        """Remove a package from the index (requires rebuild)."""
        if package_name in self.package_names:
            # For now, we need to rebuild the index to remove packages
            # FAISS doesn't support efficient removal
            logger.warning(f"Removing package '{package_name}' requires index rebuild")
            
            # Remove from metadata
            if package_name in self.package_metadata:
                del self.package_metadata[package_name]
            
            # Remove from package names and rebuild
            remaining_packages = []
            for name in self.package_names:
                if name != package_name and name in self.package_metadata:
                    metadata = self.package_metadata[name]
                    pkg = PackageFeatures(
                        name=name,
                        registry=metadata.get('registry', ''),
                        version=metadata.get('version', ''),
                        description=metadata.get('description', ''),
                        author=metadata.get('author', ''),
                        downloads=metadata.get('downloads', 0),
                        creation_date=metadata.get('creation_date', ''),
                        last_updated=metadata.get('last_updated', ''),
                        dependencies=metadata.get('dependencies', []),
                        keywords=metadata.get('keywords', []),
                        license=metadata.get('license', ''),
                        homepage=metadata.get('homepage', ''),
                        repository=metadata.get('repository', ''),
                        size=metadata.get('size', 0)
                    )
                    remaining_packages.append(pkg)
            
            self.rebuild_index(remaining_packages)
            return True
        
        return False

# Example usage and testing
if __name__ == "__main__":
    # Initialize model
    model = SemanticSimilarityModel()
    
    # Example packages
    example_packages = [
        PackageFeatures(name="react", registry="npm", description="A JavaScript library for building user interfaces"),
        PackageFeatures(name="reactjs", registry="npm", description="React library"),
        PackageFeatures(name="react-dom", registry="npm", description="React DOM bindings"),
        PackageFeatures(name="vue", registry="npm", description="Progressive JavaScript framework"),
        PackageFeatures(name="angular", registry="npm", description="Angular framework"),
        PackageFeatures(name="lodash", registry="npm", description="Utility library"),
        PackageFeatures(name="express", registry="npm", description="Web framework for Node.js"),
        PackageFeatures(name="numpy", registry="pypi", description="Scientific computing library"),
        PackageFeatures(name="pandas", registry="pypi", description="Data analysis library"),
        PackageFeatures(name="requests", registry="pypi", description="HTTP library"),
    ]
    
    # Add packages to index
    model.add_packages(example_packages)
    
    # Test similarity detection
    test_packages = ["react", "reakt", "reactt", "vue", "veu"]
    
    for pkg in test_packages:
        print(f"\nTesting package: {pkg}")
        similar = model.find_similar(pkg, top_k=5, threshold=0.7)
        for name, score in similar:
            print(f"  {name}: {score:.3f}")
        
        # Test typosquatting detection
        threats = model.detect_typosquatting(pkg, similarity_threshold=0.8)
        if threats:
            print(f"  Potential threats: {len(threats)}")
            for threat in threats[:2]:  # Show top 2 threats
                print(f"    {threat['similar_package']} (score: {threat['similarity_score']:.3f}, severity: {threat['severity']})")
    
    # Print model stats
    print(f"\nModel stats: {model.get_stats()}")
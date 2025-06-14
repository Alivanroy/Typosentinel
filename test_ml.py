#!/usr/bin/env python3
import sys
sys.path.append('ml')

try:
    from game_theory_ml import GameTheoryMLEngine
    print("Game Theory ML engine imported successfully")
    
    # Test basic functionality
    engine = GameTheoryMLEngine()
    print("Game Theory ML engine initialized successfully")
except ImportError as e:
    print(f"Import error: {e}")
except Exception as e:
    print(f"Error: {e}")
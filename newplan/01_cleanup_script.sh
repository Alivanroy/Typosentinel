#!/bin/bash
# Typosentinel Cleanup Script - Remove Science Fair Code
# This script removes all non-production ML/quantum/neural code

set -e

echo "🧹 Starting Typosentinel Cleanup..."
echo "This will remove experimental ML, quantum, and neural network code"
echo ""

# Backup first
BACKUP_DIR="./backup_$(date +%Y%m%d_%H%M%S)"
echo "Creating backup at $BACKUP_DIR..."
mkdir -p "$BACKUP_DIR"

# Function to safely remove directory
safe_remove() {
    local dir=$1
    if [ -d "$dir" ]; then
        echo "  ✓ Backing up and removing: $dir"
        cp -r "$dir" "$BACKUP_DIR/" 2>/dev/null || true
        rm -rf "$dir"
    else
        echo "  ℹ Already removed: $dir"
    fi
}

# Function to safely remove file
safe_remove_file() {
    local file=$1
    if [ -f "$file" ]; then
        echo "  ✓ Backing up and removing: $file"
        cp --parents "$file" "$BACKUP_DIR/" 2>/dev/null || true
        rm -f "$file"
    else
        echo "  ℹ Already removed: $file"
    fi
}

echo ""
echo "📁 Removing ML/Neural Network directories..."
safe_remove "internal/ml"
safe_remove "pkg/ml"

echo ""
echo "📄 Removing specific edge algorithm files..."
safe_remove_file "internal/edge/quantum.go"
safe_remove_file "internal/edge/neural.go"
safe_remove_file "internal/edge/adaptive.go"

echo ""
echo "🔒 Removing quantum security files..."
safe_remove_file "internal/security/quantum_threshold_system.go"
safe_remove_file "internal/security/steganographic_detector.go"

echo ""
echo "📝 Updating main.go to remove ML/quantum commands..."
# This is a placeholder - you'll need to manually edit main.go
# or create a sed/awk script to remove the quantum/neural flags
cat > "$BACKUP_DIR/main_go_changes.txt" << 'EOF'
MANUAL CHANGES NEEDED IN main.go:

1. Remove these command flags from edge commands:
   - --qubits
   - --neural-layers
   - --quantum-threshold
   - --adaptive-learning

2. Simplify edge command descriptions:
   BEFORE: "GTR (Graph-based Threat Recognition) uses advanced graph theory and network analysis"
   AFTER: "GTR (Graph Traversal Reconnaissance) analyzes package dependency relationships"

3. Remove any references to:
   - Quantum computing
   - Neural networks (in command descriptions)
   - Adaptive learning
   - Deep learning

4. Keep these core edge commands:
   - gtr (Graph Traversal Reconnaissance)
   - runt (Recursive Universal Network Traversal)
   - dirt (Dependency Impact Risk Traversal)
   - aicc (Adaptive Intelligence Correlation Clustering)
EOF

echo ""
echo "✅ Cleanup complete!"
echo ""
echo "📋 Summary:"
echo "  - Backup created at: $BACKUP_DIR"
echo "  - Removed: internal/ml/ directory"
echo "  - Removed: quantum/neural/adaptive files"
echo ""
echo "⚠️  MANUAL STEPS REQUIRED:"
echo "  1. Review and update main.go (see $BACKUP_DIR/main_go_changes.txt)"
echo "  2. Update edge/registry.go to remove ML algorithm registrations"
echo "  3. Run: go mod tidy"
echo "  4. Run: go build ./..."
echo "  5. Fix any import errors"
echo ""
echo "🔄 To restore from backup: cp -r $BACKUP_DIR/* ./"

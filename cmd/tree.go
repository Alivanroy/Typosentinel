package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Alivanroy/Typosentinel/internal/config"
	"github.com/Alivanroy/Typosentinel/internal/scanner"
	"github.com/Alivanroy/Typosentinel/pkg/types"
)

// treeCmd represents the tree command
var treeCmd = &cobra.Command{
	Use:   "tree [project-path]",
	Short: "Display dependency tree for a project",
	Long: `Display the dependency tree for a project in a visual format.

The tree command analyzes the project structure and displays all dependencies
in a hierarchical tree format, showing the relationships between packages.

Supported project types:
- Node.js (package.json, package-lock.json, yarn.lock)
- Python (requirements.txt, Pipfile, pyproject.toml)
- Go (go.mod)
- And more...

Example usage:
  typosentinel tree
  typosentinel tree ./my-project
  typosentinel tree --depth 3
  typosentinel tree --show-threats`,
	Args: cobra.MaximumNArgs(1),
	RunE: runTree,
}

var (
	// Tree command flags
	maxDepth     int
	showThreats  bool
	showVersions bool
	compactMode  bool
	asciiOnly    bool
	treeQuiet    bool
)

func init() {
	rootCmd.AddCommand(treeCmd)

	// Tree display flags
	treeCmd.Flags().IntVarP(&maxDepth, "depth", "d", 0, "Maximum depth to display (0 = unlimited)")
	treeCmd.Flags().BoolVar(&showThreats, "show-threats", false, "Show security threats in the tree")
	treeCmd.Flags().BoolVar(&showVersions, "show-versions", true, "Show package versions")
	treeCmd.Flags().BoolVar(&compactMode, "compact", false, "Use compact display mode")
	treeCmd.Flags().BoolVar(&asciiOnly, "ascii", false, "Use ASCII characters only (no Unicode)")
	treeCmd.Flags().BoolVarP(&treeQuiet, "quiet", "q", false, "Suppress non-essential output")
}

func runTree(cmd *cobra.Command, args []string) error {
	// Determine project path
	projectPath := "."
	if len(args) > 0 {
		projectPath = args[0]
	}

	// Convert to absolute path
	absPath, err := filepath.Abs(projectPath)
	if err != nil {
		return fmt.Errorf("failed to resolve project path: %w", err)
	}

	// Check if path exists
	if _, err := os.Stat(absPath); os.IsNotExist(err) {
		return fmt.Errorf("project path does not exist: %s", absPath)
	}

	// Load configuration
	cfg := config.NewDefaultConfig()

	// Create scanner
	scanner, err := scanner.New(cfg)
	if err != nil {
		return fmt.Errorf("failed to create scanner: %w", err)
	}

	if !treeQuiet {
		fmt.Printf("Analyzing project: %s\n", absPath)
		fmt.Println("Building dependency tree...")
		fmt.Println()
	}

	// Build dependency tree
	tree, err := scanner.BuildDependencyTree(absPath)
	if err != nil {
		return fmt.Errorf("failed to build dependency tree: %w", err)
	}

	// Render the tree
	renderer := &TreeRenderer{
		MaxDepth:     maxDepth,
		ShowThreats:  showThreats,
		ShowVersions: showVersions,
		CompactMode:  compactMode,
		ASCIIOnly:    asciiOnly,
		Quiet:        treeQuiet,
	}

	return renderer.Render(tree)
}

// TreeRenderer handles the visual rendering of dependency trees
type TreeRenderer struct {
	MaxDepth     int
	ShowThreats  bool
	ShowVersions bool
	CompactMode  bool
	ASCIIOnly    bool
	Quiet        bool
}

// Render displays the dependency tree in a visual format
func (r *TreeRenderer) Render(tree *types.DependencyTree) error {
	if tree == nil {
		return fmt.Errorf("dependency tree is nil")
	}

	// Print tree header
	if !r.Quiet {
		fmt.Printf("📦 %s\n", r.formatNode(tree, true))
	} else {
		fmt.Printf("%s\n", r.formatNode(tree, true))
	}

	// Render dependencies
	r.renderNode(tree, "", true, 0)

	// Print summary
	if !r.Quiet {
		fmt.Printf("\n📊 Summary: %d total dependencies\n", r.countDependencies(tree))
		if r.ShowThreats {
			threats := r.countThreats(tree)
			if threats > 0 {
				fmt.Printf("⚠️  Security threats found: %d\n", threats)
			} else {
				fmt.Printf("✅ No security threats detected\n")
			}
		}
	}

	return nil
}

// renderNode recursively renders a dependency tree node
func (r *TreeRenderer) renderNode(node *types.DependencyTree, prefix string, isLast bool, depth int) {
	// Check depth limit
	if r.MaxDepth > 0 && depth >= r.MaxDepth {
		return
	}

	// Render each dependency
	for i, dep := range node.Dependencies {
		isLastDep := i == len(node.Dependencies)-1

		// Choose appropriate tree characters
		var connector, childPrefix string
		if r.ASCIIOnly {
			if isLastDep {
				connector = "`-- "
				childPrefix = prefix + "    "
			} else {
				connector = "|-- "
				childPrefix = prefix + "|   "
			}
		} else {
			if isLastDep {
				connector = "└── "
				childPrefix = prefix + "    "
			} else {
				connector = "├── "
				childPrefix = prefix + "│   "
			}
		}

		// Print the dependency
		fmt.Printf("%s%s%s\n", prefix, connector, r.formatNode(&dep, false))

		// Recursively render child dependencies
		if len(dep.Dependencies) > 0 {
			r.renderNode(&dep, childPrefix, isLastDep, depth+1)
		}
	}
}

// formatNode formats a single node for display
func (r *TreeRenderer) formatNode(node *types.DependencyTree, isRoot bool) string {
	var parts []string

	// Add name
	name := fmt.Sprintf("%v", node.Name)
	parts = append(parts, name)

	// Add version if enabled
	if r.ShowVersions && node.Version != nil {
		version := fmt.Sprintf("%v", node.Version)
		if version != "" && version != "<nil>" {
			parts = append(parts, fmt.Sprintf("@%s", version))
		}
	}

	// Add type if not root
	if !isRoot && node.Type != "" {
		parts = append(parts, fmt.Sprintf("(%s)", node.Type))
	}

	result := strings.Join(parts, "")

	// Add threat indicators if enabled
	if r.ShowThreats && len(node.Threats) > 0 {
		if r.ASCIIOnly {
			result += " [THREAT]"
		} else {
			result += " ⚠️"
		}

		if !r.CompactMode {
			// Show threat details
			for _, threat := range node.Threats {
				result += fmt.Sprintf(" [%s: %s]", threat.Type, threat.Severity.String())
			}
		}
	}

	return result
}

// countDependencies recursively counts all dependencies in the tree
func (r *TreeRenderer) countDependencies(node *types.DependencyTree) int {
	count := len(node.Dependencies)
	for _, dep := range node.Dependencies {
		count += r.countDependencies(&dep)
	}
	return count
}

// countThreats recursively counts all threats in the tree
func (r *TreeRenderer) countThreats(node *types.DependencyTree) int {
	count := len(node.Threats)
	for _, dep := range node.Dependencies {
		count += r.countThreats(&dep)
	}
	return count
}

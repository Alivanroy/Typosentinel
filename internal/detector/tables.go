package detector

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

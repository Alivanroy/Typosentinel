package main

import (
	"bufio"
	"fmt"
	"os"
)

type rng struct{ start, end int }

func main() {
	path := "./main.go"
	f, err := os.Open(path)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	defer f.Close()

	ranges := []rng{
		{974, 1045},
		{1047, 1123},
		{1125, 1201},
		{1204, 1206},
		{1208, 1210},
		{1212, 1214},
		{1221, 1223},
	}

	shouldSkip := func(n int) bool {
		for _, r := range ranges {
			if n >= r.start && n <= r.end {
				return true
			}
		}
		return false
	}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 1024*1024), 1024*1024)
	var lines []string
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	var out []byte
	removed := 0
	for i, line := range lines {
		ln := i + 1
		if shouldSkip(ln) {
			removed++
			continue
		}
		out = append(out, line...)
		out = append(out, '\n')
	}

	if err := os.WriteFile(path, out, 0644); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Printf("Removed %d lines from %s\n", removed, path)
}

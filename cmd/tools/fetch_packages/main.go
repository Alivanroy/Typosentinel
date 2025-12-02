package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

// PopularPackagesData represents the structure of the output JSON file
type PopularPackagesData struct {
	NPM      []string `json:"npm"`
	PyPI     []string `json:"pypi"`
	RubyGems []string `json:"rubygems"`
	Maven    []string `json:"maven"`
	NuGet    []string `json:"nuget"`
	Default  []string `json:"default"`
}

func main() {
	fmt.Println("Fetching popular packages...")

	data := PopularPackagesData{
		Default: []string{"react", "lodash", "requests", "express"},
	}

	// Fetch PyPI
	pypiPackages, err := fetchPyPI()
	if err != nil {
		fmt.Printf("Error fetching PyPI packages: %v\n", err)
	} else {
		fmt.Printf("Fetched %d PyPI packages\n", len(pypiPackages))
		data.PyPI = pypiPackages
	}

	// Fetch NuGet
	nugetPackages, err := fetchNuGet()
	if err != nil {
		fmt.Printf("Error fetching NuGet packages: %v\n", err)
	} else {
		fmt.Printf("Fetched %d NuGet packages\n", len(nugetPackages))
		data.NuGet = nugetPackages
	}

	// Fetch NPM (Simulated/Limited for now as full list is hard)
	// In a real scenario, we might use a static list or a more complex scraper
	npmPackages, err := fetchNPM()
	if err != nil {
		fmt.Printf("Error fetching NPM packages: %v\n", err)
	} else {
		fmt.Printf("Fetched %d NPM packages\n", len(npmPackages))
		data.NPM = npmPackages
	}

	// Save to file
	outputPath := "data/popular_packages.json"
	file, err := os.Create(outputPath)
	if err != nil {
		fmt.Printf("Error creating output file: %v\n", err)
		return
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(data); err != nil {
		fmt.Printf("Error encoding JSON: %v\n", err)
		return
	}

	fmt.Printf("Successfully saved popular packages to %s\n", outputPath)
}

func fetchPyPI() ([]string, error) {
	// Source: https://hugovk.github.io/top-pypi-packages/
	url := "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.json"
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Rows []struct {
			Project string `json:"project"`
		} `json:"rows"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	var packages []string
	for _, row := range result.Rows {
		packages = append(packages, row.Project)
	}

	// Limit to 10k if needed, but the source usually has 5k-8k
	return packages, nil
}

func fetchNuGet() ([]string, error) {
	// NuGet API: https://api-v2v3search-0.nuget.org/query
	// We need to paginate
	var packages []string
	skip := 0
	take := 1000
	maxPackages := 5000 // Limit to 5000 for this demo to avoid taking too long

	for len(packages) < maxPackages {
		url := fmt.Sprintf("https://api-v2v3search-0.nuget.org/query?q=&skip=%d&take=%d&prerelease=false&semVerLevel=2.0.0", skip, take)
		resp, err := http.Get(url)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()

		var result struct {
			Data []struct {
				ID string `json:"id"`
			} `json:"data"`
		}

		if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
			return nil, err
		}

		if len(result.Data) == 0 {
			break
		}

		for _, item := range result.Data {
			packages = append(packages, item.ID)
		}

		skip += take
		time.Sleep(100 * time.Millisecond) // Be nice to the API
		fmt.Printf("Fetched %d NuGet packages...\n", len(packages))
	}

	return packages, nil
}

func fetchNPM() ([]string, error) {
	// NPM Registry Search API is limited.
	// We will use a hardcoded list of very popular packages + some search results
	// Ideally, we would download a dataset.

	// For this tool, we'll return a placeholder list of top 100 + whatever we can find
	// This is a simplified implementation.

	defaults := []string{
		"react", "react-dom", "vue", "angular", "svelte",
		"express", "koa", "fastify", "socket.io",
		"lodash", "underscore", "moment", "date-fns",
		"axios", "request", "node-fetch",
		"commander", "yargs", "chalk", "debug",
		"webpack", "rollup", "parcel", "vite",
		"babel", "typescript", "eslint", "prettier",
		"jest", "mocha", "chai", "cypress",
		"aws-sdk", "firebase", "googleapis",
		"mongoose", "sequelize", "pg", "mysql",
		"redis", "mongodb",
		"next", "nuxt", "gatsby",
		"tailwindcss", "bootstrap", "material-ui",
		"rxjs", "redux", "mobx",
		"uuid", "nanoid",
		"fs-extra", "glob", "rimraf",
		"dotenv", "cross-env",
		"nodemon", "pm2",
		"winston", "morgan",
		"jsonwebtoken", "bcrypt", "passport",
		"helmet", "cors", "body-parser",
		"multer", "sharp",
		"puppeteer", "cheerio",
		"inquirer", "ora",
		"semver", "minimist",
		"async", "bluebird",
		"classnames", "prop-types",
		"styled-components", "emotion",
	}

	return defaults, nil
}

package analyzer

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseGoDependencies(t *testing.T) {
	dir := t.TempDir()
	gomod := `module example.com/e2e-go-project

go 1.21

require (
    github.com/sirupsen/logrus v1.9.0 // indirect
    github.com/stretchr/testify v1.8.4 // indirect
)`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0o644))

	a := &Analyzer{}
	deps, err := a.parseGoDependencies(filepath.Join(dir, "go.mod"))
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(deps), 2)
	assert.Equal(t, "go", deps[0].Registry)
}

func TestParseMavenDependencies(t *testing.T) {
	dir := t.TempDir()
	pom := `<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>
  <groupId>com.example</groupId>
  <artifactId>e2e-maven-project</artifactId>
  <version>1.0.0</version>
  <dependencies>
    <dependency>
      <groupId>org.apache.commons</groupId>
      <artifactId>commons-lang3</artifactId>
      <version>3.12.0</version>
    </dependency>
    <dependency>
      <groupId>org.slf4j</groupId>
      <artifactId>slf4j-api</artifactId>
      <version>2.0.3</version>
    </dependency>
  </dependencies>
</project>`
	require.NoError(t, os.WriteFile(filepath.Join(dir, "pom.xml"), []byte(pom), 0o644))

	a := &Analyzer{}
	deps, err := a.parseMavenDependencies(filepath.Join(dir, "pom.xml"))
	require.NoError(t, err)
	assert.GreaterOrEqual(t, len(deps), 2)
	assert.Equal(t, "maven", deps[0].Registry)
}

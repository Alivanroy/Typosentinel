package main

import (
	"testing"
)

func TestValidatePackageInput_NPM(t *testing.T) {
	if err := validatePackageInput("express", "npm"); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if err := validatePackageInput("Express", "npm"); err == nil {
		t.Fatalf("expected invalid npm name")
	}
	if err := validatePackageInput("../evil", "npm"); err == nil {
		t.Fatalf("expected path traversal invalid")
	}
	if err := validatePackageInput("bad name", "npm"); err == nil {
		t.Fatalf("expected space invalid")
	}
}

func TestValidatePackageInput_PyPI(t *testing.T) {
	if err := validatePackageInput("requests", "pypi"); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if err := validatePackageInput("-bad-", "pypi"); err == nil {
		t.Fatalf("expected invalid pypi name")
	}
}

func TestValidatePackageInput_GoAndMaven(t *testing.T) {
	if err := validatePackageInput("github.com/sirupsen/logrus", "go"); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if err := validatePackageInput("org.apache.commons:commons-lang3", "maven"); err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if err := validatePackageInput("github.com/sirupsen/logrus bad", "go"); err == nil {
		t.Fatalf("expected invalid go name with spaces")
	}
	if err := validatePackageInput("org.apache.commons:commons lang3", "maven"); err == nil {
		t.Fatalf("expected invalid maven name with spaces")
	}
}

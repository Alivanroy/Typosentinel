import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';
import { PackageInfo } from '../api/apiClient';

/**
 * Supported package manager ecosystems
 */
export type Ecosystem = 'npm' | 'pip' | 'go' | 'maven' | 'gradle' | 'composer' | 'nuget' | 'cargo';

/**
 * Dependency parser for various package managers
 * Phase 1 implementation focusing on direct dependencies
 */
export class DependencyParser {
    /**
     * Parse dependencies from a manifest file
     */
    public static async parseDependencies(filePath: string): Promise<{ ecosystem: Ecosystem; packages: PackageInfo[] } | null> {
        try {
            const fileName = path.basename(filePath);
            const content = await fs.promises.readFile(filePath, 'utf8');

            switch (fileName) {
                case 'package.json':
                    return this.parsePackageJson(content);
                case 'requirements.txt':
                    return this.parseRequirementsTxt(content);
                case 'go.mod':
                    return this.parseGoMod(content);
                case 'pom.xml':
                    return this.parsePomXml(content);
                case 'build.gradle':
                case 'build.gradle.kts':
                    return this.parseBuildGradle(content);
                case 'composer.json':
                    return this.parseComposerJson(content);
                case 'Cargo.toml':
                    return this.parseCargoToml(content);
                default:
                    return null;
            }
        } catch (error) {
            console.error(`Failed to parse dependencies from ${filePath}:`, error);
            return null;
        }
    }

    /**
     * Parse package.json for npm dependencies
     */
    private static parsePackageJson(content: string): { ecosystem: Ecosystem; packages: PackageInfo[] } | null {
        try {
            const packageJson = JSON.parse(content);
            const packages: PackageInfo[] = [];

            // Parse dependencies
            if (packageJson.dependencies) {
                for (const [name, version] of Object.entries(packageJson.dependencies)) {
                    packages.push({
                        name,
                        version: this.cleanVersion(version as string)
                    });
                }
            }

            // Parse devDependencies
            if (packageJson.devDependencies) {
                for (const [name, version] of Object.entries(packageJson.devDependencies)) {
                    packages.push({
                        name,
                        version: this.cleanVersion(version as string)
                    });
                }
            }

            return { ecosystem: 'npm', packages };
        } catch (error) {
            console.error('Failed to parse package.json:', error);
            return null;
        }
    }

    /**
     * Parse requirements.txt for pip dependencies
     */
    private static parseRequirementsTxt(content: string): { ecosystem: Ecosystem; packages: PackageInfo[] } | null {
        try {
            const packages: PackageInfo[] = [];
            const lines = content.split('\n');

            for (const line of lines) {
                const trimmed = line.trim();
                if (!trimmed || trimmed.startsWith('#') || trimmed.startsWith('-')) {
                    continue;
                }

                // Parse package==version or package>=version etc.
                const match = trimmed.match(/^([a-zA-Z0-9_.-]+)([><=!~]+)([^\s;]+)/);
                if (match) {
                    packages.push({
                        name: match[1],
                        version: match[3]
                    });
                } else {
                    // Package without version
                    const nameMatch = trimmed.match(/^([a-zA-Z0-9_.-]+)/);
                    if (nameMatch) {
                        packages.push({
                            name: nameMatch[1],
                            version: '*'
                        });
                    }
                }
            }

            return { ecosystem: 'pip', packages };
        } catch (error) {
            console.error('Failed to parse requirements.txt:', error);
            return null;
        }
    }

    /**
     * Parse go.mod for Go dependencies
     */
    private static parseGoMod(content: string): { ecosystem: Ecosystem; packages: PackageInfo[] } | null {
        try {
            const packages: PackageInfo[] = [];
            const lines = content.split('\n');
            let inRequireBlock = false;

            for (const line of lines) {
                const trimmed = line.trim();

                if (trimmed.startsWith('require (')) {
                    inRequireBlock = true;
                    continue;
                }

                if (inRequireBlock && trimmed === ')') {
                    inRequireBlock = false;
                    continue;
                }

                if (inRequireBlock || trimmed.startsWith('require ')) {
                    const requireLine = trimmed.replace(/^require\s+/, '');
                    const match = requireLine.match(/^([^\s]+)\s+([^\s]+)/);
                    if (match) {
                        packages.push({
                            name: match[1],
                            version: match[2]
                        });
                    }
                }
            }

            return { ecosystem: 'go', packages };
        } catch (error) {
            console.error('Failed to parse go.mod:', error);
            return null;
        }
    }

    /**
     * Parse pom.xml for Maven dependencies (basic implementation)
     */
    private static parsePomXml(content: string): { ecosystem: Ecosystem; packages: PackageInfo[] } | null {
        try {
            const packages: PackageInfo[] = [];
            
            // Simple regex-based parsing for dependencies
            const dependencyRegex = /<dependency>[\s\S]*?<groupId>([^<]+)<\/groupId>[\s\S]*?<artifactId>([^<]+)<\/artifactId>[\s\S]*?<version>([^<]+)<\/version>[\s\S]*?<\/dependency>/g;
            
            let match;
            while ((match = dependencyRegex.exec(content)) !== null) {
                packages.push({
                    name: `${match[1]}:${match[2]}`,
                    version: match[3]
                });
            }

            return { ecosystem: 'maven', packages };
        } catch (error) {
            console.error('Failed to parse pom.xml:', error);
            return null;
        }
    }

    /**
     * Parse build.gradle for Gradle dependencies (basic implementation)
     */
    private static parseBuildGradle(content: string): { ecosystem: Ecosystem; packages: PackageInfo[] } | null {
        try {
            const packages: PackageInfo[] = [];
            
            // Simple regex-based parsing for dependencies
            const dependencyRegex = /(implementation|compile|api|testImplementation)\s+['"]([^'"]+)['"]/g;
            
            let match;
            while ((match = dependencyRegex.exec(content)) !== null) {
                const parts = match[2].split(':');
                if (parts.length >= 3) {
                    packages.push({
                        name: `${parts[0]}:${parts[1]}`,
                        version: parts[2]
                    });
                }
            }

            return { ecosystem: 'gradle', packages };
        } catch (error) {
            console.error('Failed to parse build.gradle:', error);
            return null;
        }
    }

    /**
     * Parse composer.json for PHP dependencies
     */
    private static parseComposerJson(content: string): { ecosystem: Ecosystem; packages: PackageInfo[] } | null {
        try {
            const composerJson = JSON.parse(content);
            const packages: PackageInfo[] = [];

            // Parse require
            if (composerJson.require) {
                for (const [name, version] of Object.entries(composerJson.require)) {
                    if (name !== 'php') { // Skip PHP version requirement
                        packages.push({
                            name,
                            version: this.cleanVersion(version as string)
                        });
                    }
                }
            }

            // Parse require-dev
            if (composerJson['require-dev']) {
                for (const [name, version] of Object.entries(composerJson['require-dev'])) {
                    packages.push({
                        name,
                        version: this.cleanVersion(version as string)
                    });
                }
            }

            return { ecosystem: 'composer', packages };
        } catch (error) {
            console.error('Failed to parse composer.json:', error);
            return null;
        }
    }

    /**
     * Parse Cargo.toml for Rust dependencies
     */
    private static parseCargoToml(content: string): { ecosystem: Ecosystem; packages: PackageInfo[] } | null {
        try {
            const packages: PackageInfo[] = [];
            const lines = content.split('\n');
            let inDependenciesSection = false;
            let inDevDependenciesSection = false;

            for (const line of lines) {
                const trimmed = line.trim();

                if (trimmed === '[dependencies]') {
                    inDependenciesSection = true;
                    inDevDependenciesSection = false;
                    continue;
                }

                if (trimmed === '[dev-dependencies]') {
                    inDependenciesSection = false;
                    inDevDependenciesSection = true;
                    continue;
                }

                if (trimmed.startsWith('[') && trimmed.endsWith(']')) {
                    inDependenciesSection = false;
                    inDevDependenciesSection = false;
                    continue;
                }

                if ((inDependenciesSection || inDevDependenciesSection) && trimmed.includes('=')) {
                    const match = trimmed.match(/^([^=]+)\s*=\s*['"]([^'"]+)['"]/)
                    if (match) {
                        packages.push({
                            name: match[1].trim(),
                            version: match[2]
                        });
                    }
                }
            }

            return { ecosystem: 'cargo', packages };
        } catch (error) {
            console.error('Failed to parse Cargo.toml:', error);
            return null;
        }
    }

    /**
     * Clean version string by removing prefixes like ^, ~, >=, etc.
     */
    private static cleanVersion(version: string): string {
        return version.replace(/^[^\d]*/, '').split(' ')[0];
    }

    /**
     * Get supported manifest file names
     */
    public static getSupportedManifestFiles(): string[] {
        return [
            'package.json',
            'requirements.txt',
            'go.mod',
            'pom.xml',
            'build.gradle',
            'build.gradle.kts',
            'composer.json',
            'Cargo.toml'
        ];
    }

    /**
     * Check if a file is a supported manifest file
     */
    public static isSupportedManifestFile(filePath: string): boolean {
        const fileName = path.basename(filePath);
        return this.getSupportedManifestFiles().includes(fileName);
    }

    /**
     * Get ecosystem from file path
     */
    public static getEcosystemFromFile(filePath: string): Ecosystem | null {
        const fileName = path.basename(filePath);
        
        switch (fileName) {
            case 'package.json':
                return 'npm';
            case 'requirements.txt':
                return 'pip';
            case 'go.mod':
                return 'go';
            case 'pom.xml':
                return 'maven';
            case 'build.gradle':
            case 'build.gradle.kts':
                return 'gradle';
            case 'composer.json':
                return 'composer';
            case 'Cargo.toml':
                return 'cargo';
            default:
                return null;
        }
    }
}
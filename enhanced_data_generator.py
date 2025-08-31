#!/usr/bin/env python3
"""
Enhanced Training Data Generator for TypoSentinel
Generates 20,000 realistic training examples from multiple package registries
"""

import json
import os
import random
import string
import time
from datetime import datetime, timedelta
from typing import List, Dict, Any, Tuple
import hashlib

# Real package data from different registries
REAL_NPM_PACKAGES = [
    "express", "lodash", "react", "vue", "angular", "webpack", "babel", "eslint",
    "typescript", "jest", "mocha", "chai", "axios", "moment", "underscore", "jquery",
    "bootstrap", "material-ui", "antd", "semantic-ui", "bulma", "foundation",
    "next", "nuxt", "gatsby", "svelte", "ember", "backbone", "knockout", "polymer",
    "d3", "three", "chart.js", "leaflet", "mapbox-gl", "socket.io", "ws", "express-session",
    "passport", "bcrypt", "jsonwebtoken", "cors", "helmet", "morgan", "compression",
    "nodemon", "pm2", "forever", "concurrently", "cross-env", "dotenv", "config",
    "yargs", "commander", "inquirer", "chalk", "ora", "progress", "debug",
    "fs-extra", "glob", "rimraf", "mkdirp", "path", "url", "querystring",
    "uuid", "nanoid", "shortid", "crypto-js", "bcryptjs", "validator",
    "date-fns", "dayjs", "luxon", "numeral", "big.js", "decimal.js",
    "ramda", "immutable", "immer", "redux", "mobx", "zustand", "recoil",
    "apollo-client", "graphql", "relay", "urql", "swr", "react-query",
    "styled-components", "emotion", "tailwindcss", "sass", "less", "stylus",
    "prettier", "husky", "lint-staged", "commitizen", "semantic-release",
    "storybook", "chromatic", "percy", "cypress", "playwright", "puppeteer",
    "webpack-dev-server", "vite", "rollup", "parcel", "snowpack", "esbuild"
]

REAL_PYTHON_PACKAGES = [
    "requests", "numpy", "pandas", "matplotlib", "scipy", "scikit-learn", "tensorflow",
    "pytorch", "keras", "flask", "django", "fastapi", "sqlalchemy", "alembic",
    "celery", "redis", "pymongo", "psycopg2", "mysql-connector-python", "sqlite3",
    "beautifulsoup4", "scrapy", "selenium", "requests-html", "lxml", "html5lib",
    "pillow", "opencv-python", "imageio", "moviepy", "ffmpeg-python", "pydub",
    "pytest", "unittest", "nose", "coverage", "tox", "black", "flake8", "pylint",
    "mypy", "isort", "autopep8", "yapf", "bandit", "safety", "pre-commit",
    "jupyter", "ipython", "notebook", "jupyterlab", "voila", "streamlit", "dash",
    "click", "argparse", "fire", "typer", "rich", "colorama", "termcolor",
    "pyyaml", "toml", "configparser", "python-dotenv", "environs", "dynaconf",
    "cryptography", "pycryptodome", "hashlib", "secrets", "jwt", "passlib",
    "dateutil", "arrow", "pendulum", "pytz", "babel", "locale", "gettext",
    "asyncio", "aiohttp", "aiofiles", "asyncpg", "motor", "aiomysql", "aioredis",
    "gunicorn", "uwsgi", "waitress", "hypercorn", "uvicorn", "daphne", "channels"
]

REAL_RUBY_PACKAGES = [
    "rails", "sinatra", "rack", "puma", "unicorn", "thin", "passenger", "sidekiq",
    "resque", "delayed_job", "whenever", "clockwork", "rufus-scheduler", "cron",
    "activerecord", "sequel", "mongoid", "redis-rb", "pg", "mysql2", "sqlite3",
    "devise", "omniauth", "cancancan", "pundit", "doorkeeper", "jwt", "bcrypt",
    "rspec", "minitest", "cucumber", "factory_bot", "faker", "vcr", "webmock",
    "capybara", "selenium-webdriver", "watir", "poltergeist", "chromedriver",
    "nokogiri", "mechanize", "httparty", "faraday", "rest-client", "typhoeus",
    "paperclip", "carrierwave", "shrine", "image_processing", "mini_magick",
    "sass", "less", "coffee-script", "haml", "slim", "erb", "liquid", "mustache",
    "pry", "byebug", "debug", "ruby-debug", "better_errors", "binding_of_caller",
    "rubocop", "reek", "flog", "flay", "brakeman", "bundler-audit", "simplecov",
    "capistrano", "mina", "ansible", "chef", "puppet", "docker", "kubernetes"
]

REAL_GO_PACKAGES = [
    "gin", "echo", "fiber", "chi", "mux", "httprouter", "fasthttp", "iris",
    "gorm", "xorm", "sqlx", "database/sql", "mongo-driver", "redis", "etcd",
    "grpc", "protobuf", "graphql", "websocket", "socket.io", "nats", "kafka",
    "testify", "ginkgo", "gomega", "goconvey", "mock", "counterfeiter", "viper",
    "cobra", "pflag", "kingpin", "urfave/cli", "spf13/cast", "mapstructure",
    "logrus", "zap", "zerolog", "glog", "klog", "seelog", "apex/log",
    "prometheus", "grafana", "jaeger", "opentracing", "opencensus", "otel",
    "docker", "kubernetes", "helm", "terraform", "consul", "vault", "nomad",
    "jwt-go", "oauth2", "crypto", "bcrypt", "argon2", "scrypt", "pbkdf2",
    "uuid", "shortid", "nanoid", "ulid", "ksuid", "xid", "snowflake",
    "json", "yaml", "toml", "xml", "csv", "protobuf", "msgpack", "avro"
]

REAL_RUST_PACKAGES = [
    "serde", "tokio", "async-std", "futures", "hyper", "reqwest", "actix-web",
    "warp", "rocket", "axum", "tide", "iron", "nickel", "gotham", "tower",
    "diesel", "sqlx", "sea-orm", "rusqlite", "postgres", "mysql", "mongodb",
    "clap", "structopt", "argh", "docopt", "getopts", "pico-args", "gumdrop",
    "log", "env_logger", "tracing", "slog", "flexi_logger", "fern", "simplelog",
    "anyhow", "thiserror", "eyre", "failure", "error-chain", "quick-error",
    "regex", "lazy_static", "once_cell", "parking_lot", "crossbeam", "rayon",
    "rand", "uuid", "chrono", "time", "humantime", "indicatif", "console",
    "config", "toml", "yaml-rust", "serde_json", "serde_yaml", "ron", "bincode",
    "criterion", "proptest", "quickcheck", "mockall", "rstest", "serial_test"
]

REAL_JAVA_PACKAGES = [
    "spring-boot", "spring-framework", "spring-security", "spring-data", "hibernate",
    "jackson", "gson", "apache-commons", "guava", "slf4j", "logback", "log4j",
    "junit", "testng", "mockito", "powermock", "wiremock", "rest-assured",
    "netty", "okhttp", "retrofit", "feign", "apache-httpclient", "jersey",
    "maven", "gradle", "ant", "sbt", "leiningen", "boot", "bazel", "buck"
]

# Malicious package patterns and threat types
THREAT_TYPES = [
    "typosquatting", "malware", "phishing", "data-theft", "backdoor", "trojan",
    "ransomware", "cryptominer", "keylogger", "botnet", "supply-chain", "dependency-confusion"
]

SUSPICIOUS_AUTHORS = [
    "anonymous", "hacker123", "malware-dev", "phisher", "scammer", "fake-dev",
    "suspicious-user", "unknown-author", "temp-user", "bot-account", "test-user",
    "admin", "root", "system", "null", "undefined", "deleted-user", "banned-user"
]

SUSPICIOUS_KEYWORDS = [
    "malware", "virus", "trojan", "backdoor", "exploit", "hack", "crack", "keygen",
    "bitcoin", "crypto", "mining", "miner", "wallet", "password", "steal", "phish",
    "spam", "bot", "ddos", "attack", "payload", "shell", "reverse", "bind",
    "obfuscated", "encoded", "hidden", "secret", "private", "leaked", "dump"
]

REGISTRIES = {
    "npm": {
        "real_packages": REAL_NPM_PACKAGES,
        "file_extensions": [".js", ".ts", ".jsx", ".tsx", ".json"],
        "common_deps": ["express", "lodash", "react", "vue", "webpack"],
        "version_pattern": "semver"
    },
    "pypi": {
        "real_packages": REAL_PYTHON_PACKAGES,
        "file_extensions": [".py", ".pyx", ".pyi", ".whl"],
        "common_deps": ["requests", "numpy", "pandas", "flask", "django"],
        "version_pattern": "pep440"
    },
    "rubygems": {
        "real_packages": REAL_RUBY_PACKAGES,
        "file_extensions": [".rb", ".gemspec", ".rake"],
        "common_deps": ["rails", "sinatra", "rspec", "nokogiri", "devise"],
        "version_pattern": "semver"
    },
    "crates.io": {
        "real_packages": REAL_RUST_PACKAGES,
        "file_extensions": [".rs", ".toml"],
        "common_deps": ["serde", "tokio", "clap", "regex", "anyhow"],
        "version_pattern": "semver"
    },
    "go": {
        "real_packages": REAL_GO_PACKAGES,
        "file_extensions": [".go", ".mod", ".sum"],
        "common_deps": ["gin", "gorm", "testify", "viper", "logrus"],
        "version_pattern": "semver"
    },
    "maven": {
        "real_packages": REAL_JAVA_PACKAGES,
        "file_extensions": [".jar", ".war", ".pom", ".java"],
        "common_deps": ["spring-boot", "jackson", "junit", "slf4j", "guava"],
        "version_pattern": "maven"
    }
}

class EnhancedPackageData:
    def __init__(self, name: str, version: str, description: str, author: str,
                 keywords: List[str], dependencies: Dict[str, str], downloads: int,
                 registry: str, is_malicious: bool, threat_type: str = "none", 
                 severity: float = 0.0, **kwargs):
        self.name = name
        self.version = version
        self.description = description
        self.author = author
        self.keywords = keywords
        self.dependencies = dependencies
        self.downloads = downloads
        self.registry = registry
        self.is_malicious = is_malicious
        self.threat_type = threat_type
        self.severity = severity
        
        # Additional metadata
        self.created_at = kwargs.get('created_at', self._random_date())
        self.updated_at = kwargs.get('updated_at', self.created_at)
        self.license = kwargs.get('license', self._random_license())
        self.homepage = kwargs.get('homepage', f"https://github.com/{author}/{name}")
        self.repository = kwargs.get('repository', f"git+https://github.com/{author}/{name}.git")
        self.file_count = kwargs.get('file_count', random.randint(1, 100))
        self.size_bytes = kwargs.get('size_bytes', random.randint(1024, 10485760))  # 1KB to 10MB
        self.maintainers = kwargs.get('maintainers', [author] + [self._random_author() for _ in range(random.randint(0, 3))])
        self.tags = kwargs.get('tags', [])
        
    def _random_date(self):
        start_date = datetime.now() - timedelta(days=365*5)  # 5 years ago
        end_date = datetime.now()
        time_between = end_date - start_date
        days_between = time_between.days
        random_days = random.randrange(days_between)
        return (start_date + timedelta(days=random_days)).isoformat()
    
    def _random_license(self):
        licenses = ["MIT", "Apache-2.0", "GPL-3.0", "BSD-3-Clause", "ISC", "LGPL-2.1", "MPL-2.0", "Unlicense"]
        return random.choice(licenses)
    
    def _random_author(self):
        first_names = ["john", "jane", "alex", "sarah", "mike", "lisa", "david", "emma", "chris", "anna"]
        last_names = ["smith", "johnson", "brown", "davis", "miller", "wilson", "moore", "taylor", "anderson", "thomas"]
        return f"{random.choice(first_names)}.{random.choice(last_names)}"
    
    def to_dict(self):
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "author": self.author,
            "keywords": self.keywords,
            "dependencies": self.dependencies,
            "downloads": self.downloads,
            "registry": self.registry,
            "is_malicious": self.is_malicious,
            "threat_type": self.threat_type,
            "severity": self.severity,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "license": self.license,
            "homepage": self.homepage,
            "repository": self.repository,
            "file_count": self.file_count,
            "size_bytes": self.size_bytes,
            "maintainers": self.maintainers,
            "tags": self.tags
        }

def generate_version(pattern: str) -> str:
    """Generate realistic version numbers based on pattern"""
    if pattern == "semver":
        major = random.randint(0, 10)
        minor = random.randint(0, 20)
        patch = random.randint(0, 50)
        if random.random() < 0.1:  # 10% chance of pre-release
            pre = random.choice(["alpha", "beta", "rc"])
            pre_num = random.randint(1, 5)
            return f"{major}.{minor}.{patch}-{pre}.{pre_num}"
        return f"{major}.{minor}.{patch}"
    elif pattern == "pep440":
        major = random.randint(0, 5)
        minor = random.randint(0, 20)
        micro = random.randint(0, 50)
        if random.random() < 0.15:  # 15% chance of dev/pre-release
            if random.random() < 0.5:
                return f"{major}.{minor}.{micro}.dev{random.randint(1, 10)}"
            else:
                pre = random.choice(["a", "b", "rc"])
                return f"{major}.{minor}.{micro}{pre}{random.randint(1, 5)}"
        return f"{major}.{minor}.{micro}"
    elif pattern == "maven":
        major = random.randint(1, 10)
        minor = random.randint(0, 20)
        patch = random.randint(0, 50)
        if random.random() < 0.1:  # 10% chance of snapshot
            return f"{major}.{minor}.{patch}-SNAPSHOT"
        return f"{major}.{minor}.{patch}"
    else:
        return f"{random.randint(1, 5)}.{random.randint(0, 10)}.{random.randint(0, 20)}"

def create_typosquatting_name(original: str) -> str:
    """Create typosquatting variants of package names"""
    techniques = [
        lambda x: x + 's',  # Add 's'
        lambda x: x + 'js',  # Add 'js'
        lambda x: x.replace('e', '3'),  # Replace 'e' with '3'
        lambda x: x.replace('o', '0'),  # Replace 'o' with '0'
        lambda x: x.replace('i', '1'),  # Replace 'i' with '1'
        lambda x: x.replace('l', '1'),  # Replace 'l' with '1'
        lambda x: x.replace('-', '_'),  # Replace '-' with '_'
        lambda x: x.replace('_', '-'),  # Replace '_' with '-'
        lambda x: x[:-1] if len(x) > 3 else x,  # Remove last character
        lambda x: x + x[-1] if len(x) > 2 else x,  # Double last character
        lambda x: ''.join([c for i, c in enumerate(x) if i != len(x)//2]),  # Remove middle character
        lambda x: x[:2] + x[2:].replace(x[2], x[2].upper(), 1) if len(x) > 2 else x,  # Capitalize middle
    ]
    
    technique = random.choice(techniques)
    result = technique(original)
    
    # Ensure it's different from original
    if result == original and len(original) > 3:
        result = original[:-1] + random.choice('sxz')
    
    return result

def generate_benign_packages(count: int, registry_weights: Dict[str, float]) -> List[EnhancedPackageData]:
    """Generate realistic benign packages from different registries"""
    packages = []
    
    for _ in range(count):
        # Choose registry based on weights
        registry = random.choices(
            list(registry_weights.keys()),
            weights=list(registry_weights.values())
        )[0]
        
        registry_info = REGISTRIES[registry]
        
        # Choose base package (80% real, 20% generated)
        if random.random() < 0.8:
            base_name = random.choice(registry_info["real_packages"])
            # Sometimes add suffix for variations
            if random.random() < 0.3:
                suffixes = ["-utils", "-helper", "-core", "-lib", "-tools", "-cli", "-api"]
                name = base_name + random.choice(suffixes)
            else:
                name = base_name
        else:
            # Generate realistic name
            prefixes = ["awesome", "super", "ultra", "mega", "pro", "advanced", "simple", "easy"]
            suffixes = ["lib", "tool", "util", "helper", "core", "framework", "engine", "service"]
            name = f"{random.choice(prefixes)}-{random.choice(suffixes)}"
        
        # Generate realistic author
        if random.random() < 0.7:
            # Individual developer
            first_names = ["john", "jane", "alex", "sarah", "mike", "lisa", "david", "emma", "chris", "anna"]
            last_names = ["smith", "johnson", "brown", "davis", "miller", "wilson", "moore", "taylor"]
            author = f"{random.choice(first_names)}.{random.choice(last_names)}"
        else:
            # Organization
            orgs = ["facebook", "google", "microsoft", "netflix", "airbnb", "uber", "twitter",
                   "github", "gitlab", "atlassian", "mozilla", "apache", "nodejs", "team"]
            author = random.choice(orgs)
        
        # Generate description
        adjectives = ["fast", "reliable", "modern", "lightweight", "powerful", "simple", "elegant"]
        nouns = ["library", "framework", "utility", "tool", "component", "service", "module"]
        purposes = ["web development", "data processing", "testing", "building", "deployment"]
        description = f"A {random.choice(adjectives)} {random.choice(nouns)} for {random.choice(purposes)}"
        
        # Generate keywords
        keyword_pools = {
            "npm": ["javascript", "nodejs", "web", "frontend", "backend", "framework", "library"],
            "pypi": ["python", "data", "science", "machine-learning", "web", "api", "automation"],
            "rubygems": ["ruby", "rails", "web", "framework", "gem", "library", "tool"],
            "crates.io": ["rust", "systems", "performance", "memory-safe", "concurrent", "cli"],
            "go": ["golang", "concurrent", "microservices", "cloud", "devops", "cli"],
            "maven": ["java", "enterprise", "spring", "web", "framework", "library"]
        }
        keywords = random.sample(keyword_pools.get(registry, ["library", "tool"]), random.randint(2, 5))
        
        # Generate dependencies
        common_deps = registry_info["common_deps"]
        dep_count = random.randint(0, 8)
        dependencies = {}
        for _ in range(dep_count):
            dep_name = random.choice(common_deps + registry_info["real_packages"])
            dep_version = f"^{generate_version(registry_info['version_pattern'])}"
            dependencies[dep_name] = dep_version
        
        # Generate realistic download counts (higher for benign)
        download_ranges = {
            "npm": (1000, 50000000),
            "pypi": (500, 10000000),
            "rubygems": (100, 5000000),
            "crates.io": (50, 1000000),
            "go": (100, 2000000),
            "maven": (200, 8000000)
        }
        min_downloads, max_downloads = download_ranges.get(registry, (100, 1000000))
        downloads = random.randint(min_downloads, max_downloads)
        
        package = EnhancedPackageData(
            name=name,
            version=generate_version(registry_info["version_pattern"]),
            description=description,
            author=author,
            keywords=keywords,
            dependencies=dependencies,
            downloads=downloads,
            registry=registry,
            is_malicious=False,
            threat_type="none",
            severity=0.0
        )
        
        packages.append(package)
    
    return packages

def generate_malicious_packages(count: int, registry_weights: Dict[str, float]) -> List[EnhancedPackageData]:
    """Generate realistic malicious packages with various threat patterns"""
    packages = []
    
    for _ in range(count):
        # Choose registry
        registry = random.choices(
            list(registry_weights.keys()),
            weights=list(registry_weights.values())
        )[0]
        
        registry_info = REGISTRIES[registry]
        threat_type = random.choice(THREAT_TYPES)
        severity = random.uniform(0.3, 1.0)
        
        # Generate malicious name based on threat type
        if threat_type == "typosquatting":
            # Create typosquatting variant
            original = random.choice(registry_info["real_packages"])
            name = create_typosquatting_name(original)
        elif threat_type == "dependency-confusion":
            # Use internal-sounding names
            prefixes = ["internal", "private", "corp", "company", "org", "team"]
            suffixes = ["utils", "core", "lib", "tools", "config", "secrets"]
            name = f"{random.choice(prefixes)}-{random.choice(suffixes)}"
        else:
            # Other malicious patterns
            if random.random() < 0.4:
                # Suspicious names
                suspicious_words = ["hack", "crack", "exploit", "payload", "shell", "backdoor"]
                name = f"{random.choice(suspicious_words)}-{random.choice(['tool', 'lib', 'util'])}"
            else:
                # Seemingly innocent names
                innocent_words = ["helper", "utility", "common", "shared", "basic", "simple"]
                name = f"{random.choice(innocent_words)}-{random.choice(['lib', 'utils', 'tools'])}"
        
        # Generate suspicious author
        if random.random() < 0.6:
            author = random.choice(SUSPICIOUS_AUTHORS)
        else:
            # Sometimes use legitimate-looking names
            author = f"user{random.randint(1000, 9999)}"
        
        # Generate suspicious description
        if threat_type in ["malware", "trojan", "backdoor"]:
            descriptions = [
                "Utility package for system operations",
                "Helper library for advanced functionality",
                "Core utilities for application development",
                "System tools and utilities",
                "Advanced helper functions"
            ]
        elif threat_type == "cryptominer":
            descriptions = [
                "Cryptocurrency utilities and tools",
                "Blockchain helper library",
                "Mining optimization tools",
                "Crypto processing utilities"
            ]
        else:
            descriptions = [
                "Suspicious package with unknown functionality",
                "Potentially harmful utility package",
                "Unverified system tools",
                "Questionable helper library"
            ]
        description = random.choice(descriptions)
        
        # Generate suspicious keywords
        base_keywords = random.sample(SUSPICIOUS_KEYWORDS, random.randint(1, 3))
        if threat_type == "cryptominer":
            base_keywords.extend(["crypto", "mining", "bitcoin"])
        elif threat_type == "typosquatting":
            # Mix with legitimate keywords to appear innocent
            legit_keywords = ["utility", "helper", "library", "framework"]
            base_keywords.extend(random.sample(legit_keywords, 2))
        
        keywords = base_keywords[:5]  # Limit to 5 keywords
        
        # Generate minimal dependencies (malicious packages often have fewer deps)
        dependencies = {}
        if random.random() < 0.3:  # Only 30% have dependencies
            dep_count = random.randint(1, 3)
            common_deps = registry_info["common_deps"]
            for _ in range(dep_count):
                dep_name = random.choice(common_deps)
                dep_version = f"^{generate_version(registry_info['version_pattern'])}"
                dependencies[dep_name] = dep_version
        
        # Generate low download counts (suspicious packages typically have low adoption)
        downloads = random.randint(1, 5000)
        
        package = EnhancedPackageData(
            name=name,
            version=generate_version(registry_info["version_pattern"]),
            description=description,
            author=author,
            keywords=keywords,
            dependencies=dependencies,
            downloads=downloads,
            registry=registry,
            is_malicious=True,
            threat_type=threat_type,
            severity=severity,
            file_count=random.randint(1, 20),  # Fewer files
            size_bytes=random.randint(512, 1048576)  # Smaller size
        )
        
        packages.append(package)
    
    return packages

def generate_enhanced_dataset(total_count: int = 20000, malicious_ratio: float = 0.25) -> List[EnhancedPackageData]:
    """Generate enhanced dataset with realistic distribution across registries"""
    print(f"Generating enhanced dataset with {total_count} samples...")
    
    # Registry distribution (based on real-world usage)
    registry_weights = {
        "npm": 0.35,      # JavaScript/Node.js - most popular
        "pypi": 0.25,     # Python - very popular
        "maven": 0.15,    # Java - enterprise
        "rubygems": 0.10, # Ruby
        "crates.io": 0.08, # Rust - growing
        "go": 0.07        # Go - cloud/devops
    }
    
    malicious_count = int(total_count * malicious_ratio)
    benign_count = total_count - malicious_count
    
    print(f"Generating {benign_count} benign packages...")
    benign_packages = generate_benign_packages(benign_count, registry_weights)
    
    print(f"Generating {malicious_count} malicious packages...")
    malicious_packages = generate_malicious_packages(malicious_count, registry_weights)
    
    # Combine and shuffle
    all_packages = benign_packages + malicious_packages
    random.shuffle(all_packages)
    
    print(f"Generated {len(all_packages)} total packages")
    print(f"Registry distribution:")
    for registry in registry_weights.keys():
        count = sum(1 for p in all_packages if p.registry == registry)
        percentage = (count / len(all_packages)) * 100
        print(f"  {registry}: {count} packages ({percentage:.1f}%)")
    
    print(f"Threat type distribution:")
    threat_counts = {}
    for package in all_packages:
        threat_type = package.threat_type
        threat_counts[threat_type] = threat_counts.get(threat_type, 0) + 1
    
    for threat_type, count in sorted(threat_counts.items()):
        percentage = (count / len(all_packages)) * 100
        print(f"  {threat_type}: {count} packages ({percentage:.1f}%)")
    
    return all_packages

def save_enhanced_dataset(packages: List[EnhancedPackageData], output_path: str):
    """Save the enhanced dataset to JSON file"""
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    
    # Convert to dictionaries
    package_dicts = [pkg.to_dict() for pkg in packages]
    
    # Save to file
    with open(output_path, 'w') as f:
        json.dump(package_dicts, f, indent=2)
    
    print(f"Enhanced dataset saved to: {output_path}")
    print(f"File size: {os.path.getsize(output_path) / (1024*1024):.2f} MB")

def main():
    """Main function to generate enhanced training dataset"""
    print("Enhanced TypoSentinel Training Data Generator")
    print("=" * 50)
    print(f"Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Set random seed for reproducibility
    random.seed(42)
    
    # Generate enhanced dataset
    start_time = time.time()
    packages = generate_enhanced_dataset(total_count=20000, malicious_ratio=0.25)
    generation_time = time.time() - start_time
    
    print(f"\nDataset generation completed in {generation_time:.2f} seconds")
    
    # Save dataset
    output_path = "./data/training/enhanced_training_samples.json"
    save_enhanced_dataset(packages, output_path)
    
    # Generate statistics
    print("\nDataset Statistics:")
    print(f"Total packages: {len(packages)}")
    print(f"Benign packages: {sum(1 for p in packages if not p.is_malicious)}")
    print(f"Malicious packages: {sum(1 for p in packages if p.is_malicious)}")
    
    # Registry statistics
    registry_stats = {}
    for package in packages:
        registry = package.registry
        if registry not in registry_stats:
            registry_stats[registry] = {'total': 0, 'benign': 0, 'malicious': 0}
        registry_stats[registry]['total'] += 1
        if package.is_malicious:
            registry_stats[registry]['malicious'] += 1
        else:
            registry_stats[registry]['benign'] += 1
    
    print("\nRegistry breakdown:")
    for registry, stats in registry_stats.items():
        print(f"  {registry}: {stats['total']} total ({stats['benign']} benign, {stats['malicious']} malicious)")
    
    print(f"\n🎉 Enhanced dataset generation completed!")
    print(f"Dataset saved to: {output_path}")
    print(f"Ready for neural network training with {len(packages)} samples")

if __name__ == "__main__":
    main()
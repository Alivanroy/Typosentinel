import os
import sys
import subprocess

# --- Installation ---
try:
    import tiktoken
except ImportError:
    print("tiktoken library not found. Installing...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", "tiktoken"])
        import tiktoken
        print("tiktoken installed successfully.")
    except Exception as e:
        print(f"Error: Failed to install tiktoken. Please install it manually: pip install tiktoken")
        print(f"Details: {e}")
        sys.exit(1)

# --- Configuration ---
output_filename = "CONSOLIDATED_PROJECT_MINIMIZED.txt"
max_tokens = 1_000_000
ENCODING_NAME = "cl100k_base"

# --- Inclusion Rules (Allow-List) ---
# Define specific directories and files to prioritize.
INCLUDED_PATHS = {
    "main.go",
    "go.mod",
    "docker-compose.yml",
    "Dockerfile",
    "cmd/",
    "internal/config/",
    "internal/scanner/",
    "internal/detector/",
    "internal/static/",
    "internal/ml/client.go",
    "ml/service/api_server.py",
    "ml/models/malicious_classifier.py",
    "ml/models/semantic_similarity.py",
    "web/src/App.tsx",
    "web/src/pages/enterprise/ExecutiveDashboard.tsx",
    "web/src/services/api.ts",
    "PROJECT_GUIDE.md", # Include the guide for context
}

# --- Main Script Logic ---

def is_path_included(filepath):
    """Check if a file path matches the inclusion criteria."""
    filepath = filepath.replace(os.sep, "/")
    for included_path in INCLUDED_PATHS:
        if filepath.startswith(included_path):
            return True
    return False

def main():
    """Walks the project tree and consolidates files based on an allow-list."""
    total_tokens = 0
    files_included = 0
    files_skipped = 0

    try:
        encoding = tiktoken.get_encoding(ENCODING_NAME)
    except Exception as e:
        print(f"Error getting tiktoken encoding: {e}")
        return

    all_files = []
    for dirpath, _, filenames in os.walk("."):
        for filename in filenames:
            full_path = os.path.join(dirpath, filename).lstrip('./')
            if is_path_included(full_path):
                all_files.append(full_path)
    
    print(f"Found {len(all_files)} files matching the inclusion criteria.")

    with open(output_filename, "w", encoding="utf-8", errors="ignore") as outfile:
        for filepath in sorted(all_files):
            try:
                with open(filepath, "r", encoding="utf-8", errors="ignore") as infile:
                    content = infile.read()
                
                header = f"--- START OF {filepath} ---\n"
                footer = f"\n--- END OF {filepath} ---\n\n"
                
                # Calculate token count for the current file and its headers
                file_tokens = len(encoding.encode(content))
                header_tokens = len(encoding.encode(header))
                footer_tokens = len(encoding.encode(footer))
                total_file_tokens = file_tokens + header_tokens + footer_tokens

                if total_tokens + total_file_tokens > max_tokens:
                    print(f"Skipping {filepath} ({file_tokens} tokens) - would exceed the {max_tokens:,} token limit.")
                    files_skipped += 1
                    continue

                outfile.write(header)
                outfile.write(content)
                outfile.write(footer)
                
                total_tokens += total_file_tokens
                files_included += 1

            except Exception as e:
                print(f"Could not read or process file {filepath}: {e}")
                files_skipped += 1

    print(f"\n--- Consolidation Summary ---")
    print(f"Consolidated project into {output_filename}")
    print(f"Total tokens: {total_tokens:,}")
    print(f"Files included: {files_included}")
    print(f"Files skipped: {len(all_files) - files_included}")
    if total_tokens > max_tokens:
        print(f"WARNING: Final token count ({total_tokens:,}) exceeds the limit of {max_tokens:,}.")

if __name__ == "__main__":
    main()
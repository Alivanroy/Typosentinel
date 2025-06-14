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
FILENAME = "CONSOLIDATED_PROJECT.txt"
# Use a common encoding for GPT models
ENCODING_NAME = "cl100k_base" 

# --- Main Script Logic ---
def count_tokens_in_file(filename):
    """Reads a file and counts the tokens using tiktoken."""
    try:
        # Get the encoding
        encoding = tiktoken.get_encoding(ENCODING_NAME)
    except Exception as e:
        print(f"Error: Could not get the encoding '{ENCODING_NAME}'.")
        print(f"Details: {e}")
        return None

    try:
        with open(filename, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
            
        # Encode the content to get the token integers
        tokens = encoding.encode(content)
        
        return len(tokens)
        
    except FileNotFoundError:
        print(f"Error: The file '{filename}' was not found.")
        return None
    except Exception as e:
        print(f"An error occurred while processing the file: {e}")
        return None

def main():
    """Main function to run the token counting."""
    if not os.path.exists(FILENAME):
        print(f"Error: The file '{FILENAME}' does not exist. Please create it first.")
        return

    print(f"Counting tokens in '{FILENAME}' using '{ENCODING_NAME}' encoding...")
    
    token_count = count_tokens_in_file(FILENAME)
    
    if token_count is not None:
        print(f"\n--- Token Count Summary ---")
        print(f"Total tokens in {FILENAME}: {token_count:,}")

if __name__ == "__main__":
    main()
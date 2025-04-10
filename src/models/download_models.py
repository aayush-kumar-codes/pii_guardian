import spacy
import sys
import subprocess
import pkg_resources

def main():
    """Download required spaCy models"""
    print("Checking for spaCy...")
    try:
        spacy_version = pkg_resources.get_distribution("spacy").version
        print(f"spaCy version {spacy_version} found")
    except pkg_resources.DistributionNotFound:
        print("spaCy not found. Installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", "spacy"])
    
    # Download English model
    print("Downloading English language model...")
    subprocess.check_call([sys.executable, "-m", "spacy", "download", "en_core_web_sm"])
    
    print("Models downloaded successfully")

if __name__ == "__main__":
    main()

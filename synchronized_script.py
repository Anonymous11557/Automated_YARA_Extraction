import os
import hashlib
import json
import pandas as pd
from sklearn.preprocessing import LabelEncoder
from yara_v2 import parse_yara_rule

# === CONFIGURATION ===
YARA_DIR = "extracted_yara_files"
HASH_RECORD_FILE = "seen_files.json"
CSV_PATH = "yara_dataset.csv"

# === UTILITY FUNCTIONS ===
def hash_file(filepath):
    """Compute SHA256 hash of a file."""
    h = hashlib.sha256()
    with open(filepath, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b''):
            h.update(chunk)
    return h.hexdigest()

def load_seen_hashes():
    """Load seen file hashes from JSON."""
    if not os.path.exists(HASH_RECORD_FILE):
        print(" No seen_files.json found. Starting fresh.")
        return set()
    with open(HASH_RECORD_FILE, 'r') as f:
        try:
            data = json.load(f)
            return set(data.get("seen_hashes", []))
        except Exception as e:
            print(f"Failed to read JSON: {e}")
            return set()

def save_seen_hashes(seen_hashes):
    """Save updated seen hashes back to JSON."""
    with open(HASH_RECORD_FILE, 'w') as f:
        json.dump({"seen_hashes": list(seen_hashes)}, f, indent=2)

# === FEATURE EXTRACTION ===
def extract_features_from_new_yara_files(seen_hashes):
    features = []
    labels = []
    new_hashes = []

    for filename in os.listdir(YARA_DIR):
        filepath = os.path.join(YARA_DIR, filename)

        if not filename.endswith((".yar", ".yara")):
            print(f"Skipping non-YARA file: {filename}")
            continue

        file_hash = hash_file(filepath)
        if file_hash in seen_hashes:
            # print(f"Already processed: {filename}")
            continue

        try:
            
            parsed_rules = parse_yara_rule(filepath)
           

            for rule in parsed_rules:
                features.append(rule)
                labels.append("malware")  # You can customize this label if needed

            new_hashes.append(file_hash)
            

        except Exception as e:
            print(f"Error parsing {filename}: {e}")

    return features, labels, new_hashes

# === MAIN EXECUTION ===
def main():
    print("\n=== Starting Feature Extraction ===")
    seen_hashes = load_seen_hashes()
    X, y_labels, new_hashes = extract_features_from_new_yara_files(seen_hashes)

    if not X:
        print("✅ No new YARA rules to process.")
        return

    families = [rule.get("family", "unknown") for rule in X]
    le = LabelEncoder()
    class_encoded = le.fit_transform(families)
    label_encoded = [1] * len(y_labels)

    df_new = pd.DataFrame(X)
    df_new["class"] = class_encoded
    df_new["label"] = label_encoded

    # Append to or create CSV
    if os.path.exists(CSV_PATH):
        df_existing = pd.read_csv(CSV_PATH)
        df_combined = pd.concat([df_existing, df_new], ignore_index=True)
    else:
        df_combined = df_new

    df_combined.to_csv(CSV_PATH, index=False)
    print(f" Dataset updated at: {CSV_PATH} ({len(df_new)} new rows)")

    # Save updated hashes
    updated_hashes = seen_hashes.union(new_hashes)
    save_seen_hashes(updated_hashes)
    print("Hash record updated in seen_files.json.")

if __name__ == "__main__":
    main()

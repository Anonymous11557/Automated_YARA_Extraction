import os
import time
import hashlib
import schedule
from git import Repo
from pathlib import Path
import shutil
import subprocess 
import sys
import json

# === CONFIGURATION ===
# Add more repositories here
REPO_LIST = [
    
    "https://github.com/Yara-Rules/rules.git",
    "https://github.com/anyrun/YARA.git",
    "https://github.com/CyberDefenses/CDI_yara.git",
    "https://github.com/stvemillertime/ConventionEngine.git",
    "https://github.com/Neo23x0/signature-base",
    "https://github.com/mandiant/red_team_tool_countermeasures.git",
    "https://github.com/elastic/protections-artifacts.git",
    "https://github.com/DidierStevens/DidierStevensSuite.git",
    "https://github.com/deadbits/yara-rules.git",
    "https://github.com/kevoreilly/CAPE.git",
    "https://github.com/eset/malware-ioc.git",
    "https://github.com/MalGamy/YARA_Rules.git",
    "https://github.com/citizenlab/malware-signatures.git",
    "https://github.com/CyberDefenses/CDI_yara.git",
    "https://github.com/kevoreilly/CAPEv2.git",
    "https://github.com/codewatchorg/Burp-Yara-Rules.git",
    "https://github.com/bartblaze/Yara-rules.git",
    "https://gist.github.com/c586a151a978f971b70412ca4485c491.git",
    "https://github.com/InQuest/awesome-yara.git",
    "https://github.com/reversinglabs/reversinglabs-yara-rules.git",
    "https://github.com/airbnb/binaryalert.git",
    "https://github.com/karttoon/binsequencer.git",
    "https://github.com/delivr-to/detections.git",
    "https://github.com/ditekshen/detection.git",
    "https://github.com/filescanio/fsYara.git",
    "https://gist.github.com/f1bb645a4f715cb499150c5a14d82b44.git",
    "https://github.com/f0wl/yara_rules.git",
    "https://github.com/fboldewin/YARA-rules.git",
    "https://github.com/EmersonElectricCo/fsf.git",
    "https://github.com/godaddy/yara-rules.git",#
    "https://github.com/chronicle/GCTI.git",
    "https://github.com/h3x2b/yara-rules.git",
    "https://github.com/HydraDragonAntivirus/HydraDragonAntivirus.git",
    "https://github.com/imp0rtp3/yara-rules.git",
    "https://github.com/intezer/yara-rules.git",
    "https://github.com/jeFF0Falltrades/YARA-Signatures.git",
    "https://github.com/Hestat/lw-yara.git",
    "https://github.com/nccgroup/Cyber-Defence.git",
    "https://github.com/malice-plugins/yara.git",#
    "https://github.com/advanced-threat-research/Yara-Rules.git",
    "https://github.com/jipegit/yara-rules-public.git",
    "https://github.com/securitymagic/yara.git",
    "https://github.com/telekom-security/malware_analysis.git",
    "https://github.com/Xumeiquer/yara-forensics.git",
    "https://github.com/fr0gger/Yara-Unprotect.git",
    "https://github.com/wrayjustin/yaids.git",
    "https://github.com/tenable/yara-rules.git",
    "https://github.com/mthcht/ThreatHunting-Keywords-yara-rules.git",
    "https://github.com/SpiderLabs/malware-analysis.git"
]
CLONE_DIR = Path("cloned_repos")
EXTRACT_DIR = Path("extracted_yara_files")
FILE_RECORD_PATH = Path("seen_files.json")
CHECK_INTERVAL_HOURS = 1
# 
# === INITIAL SETUP ===
CLONE_DIR.mkdir(exist_ok=True)
EXTRACT_DIR.mkdir(exist_ok=True)

def hash_file(file_path):
    """Returns SHA256 hash of a file, or None if unreadable."""
    h = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            h.update(f.read())
        return h.hexdigest()
    except (OSError, IOError) as e:
        print(f" Skipping unreadable file: {file_path} ({e})")
        return None

def load_seen_files():
    if FILE_RECORD_PATH.exists():
        with open(FILE_RECORD_PATH, 'r') as f:
            return json.load(f)
    return {}  # {file_path: mod_time}


def save_seen_files(record):
    with open(FILE_RECORD_PATH, 'w') as f:
        json.dump(record, f, indent=2)


def sanitize_repo_name(repo_url):
    name = repo_url.rstrip("/").split("/")[-1]
    return name.replace(".git", "")
    
def clone_or_pull(repo_url):
    repo_name = sanitize_repo_name(repo_url)
    repo_path = CLONE_DIR / repo_name

    if repo_path.exists():
        print(f"Pulling updates from {repo_name}...")
        repo = Repo(repo_path)
        repo.remotes.origin.pull()
    else:
        print(f"Cloning {repo_name}...")
        Repo.clone_from(repo_url, repo_path)

    return repo_path


def extract_yara_files(repo_path):
    seen_files = load_seen_files()
    updated_seen = seen_files.copy()
    new_files = []

    for root, _, files in os.walk(repo_path):
        for file in files:
            if file.endswith((".yara", ".yar")):
                full_path = str(Path(root) / file)
                try:
                    mod_time = os.path.getmtime(full_path)
                except Exception as e:
                    print(f"Could not access {full_path}: {e}")
                    continue

                if full_path not in seen_files or seen_files[full_path] != mod_time:
                    dest_path = EXTRACT_DIR / f"{Path(file).stem}_{int(mod_time)}.yar"
                    shutil.copy2(full_path, dest_path)
                    new_files.append(dest_path)
                    updated_seen[full_path] = mod_time

    # if new_files:
    #     python_exec = sys.executable 
    #     print("Triggering feature extraction...")
    #     subprocess.run([python_exec, "synchronized_script.py"])

    save_seen_files(updated_seen)
    return new_files



def job():
    print("\n=== Running GitHub YARA Crawler Job ===")
    for repo_url in REPO_LIST:
        repo_path = clone_or_pull(repo_url)
        new_files = extract_yara_files(repo_path)
        print(f"Found {len(new_files)} new YARA files in {repo_url}")
        # If new files found, call the extractor
        if new_files:
            python_exec = sys.executable 
            print("Triggering feature extraction...")
            subprocess.run([python_exec, "synchronized_script.py"])  

# Schedule job
schedule.every(CHECK_INTERVAL_HOURS).hours.do(job)
# Run once immediately
job()

print(f"\nScheduler started. Checking every {CHECK_INTERVAL_HOURS} hours...")
while True:
    schedule.run_pending()
    time.sleep(60)

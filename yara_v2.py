import re
import os
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
from sklearn.metrics import accuracy_score
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from collections import defaultdict
from pathlib import Path


import ast
def splitter2(value):
    string_count = 0
    value = value.strip()
    if value.startswith('[') and value.endswith(']'):
        try:
            my_list = ast.literal_eval(value)
            #print(my_list)
            for item in my_list:
                item = item.strip()
                print(item)
                print()
                splitter2(item)
                string_count += 1
        except Exception:
            print(value+" contains only one item")

def extract_yara_rules(yara_text):
    rules = []
    current_rule = ""
    inside_rule = False
    brace_count = 0

    for line in yara_text:
        stripped = line.strip()

        if stripped.startswith("rule "):
            inside_rule = True
            current_rule = line
            brace_count = line.count("{") - line.count("}")

        elif inside_rule:
            current_rule += line
            brace_count += line.count("{") - line.count("}")

            if brace_count == 0:
                rules.append(current_rule)
                inside_rule = False
                current_rule = ""
    
    rules_data = []  
    for rule_text in rules:
        rule_data = {}

        # Get rule body
        body_match = re.search(r'\{(.*)\}', rule_text, re.DOTALL)
        rule_body = body_match.group(1) if body_match else ""

        # Get rule name
        name_match = re.search(r'rule\s+(\w+)', rule_text)
        rule_data['rule_name'] = name_match.group(1) if name_match else "Unknown"

        if "_" in rule_data['rule_name']:
            parts = rule_data['rule_name'].split("_")
        
            # Remove parts 
            cleaned_parts = [
                part for part in parts 
                if not re.search(r'(apt|malware|apt1|apr17)', part, re.IGNORECASE)
            ]
            
            # Reconstruct the rule name
            rule_data['rule_name'] = "_".join(cleaned_parts)
        else:
            rule_data['rule_name'] 

        # Check if rule_name ends with or contains a long hex string
        if re.search(r'[a-fA-F0-9]{16,}', rule_data['rule_name']):
            meta_match = re.search(
                r'meta:\s*(.*?)(?=\bstrings:|\bcondition:|\})', rule_body, re.DOTALL | re.IGNORECASE
            )
            if meta_match:
                meta_block = meta_match.group(1)
                desc_match = re.search(r'description\s*=\s*"([^"]+)"', meta_block)
                if desc_match:
                    rule_data['rule_name'] = desc_match.group(1).strip()
                else:
                    rule_data['rule_name']
            else:
                rule_data['rule_name']

        meta_match = re.search(r'meta:\s*(.*?)(?=^\s*(strings:|condition:|\}))', rule_body, re.DOTALL | re.IGNORECASE | re.MULTILINE)
        meta_block = meta_match.group(1) if meta_match else ""
        appeared_value = None

        # Extract hashes from meta
        md5_match = re.search(r'md5\s*=\s*"([^"]+)"', meta_block, re.IGNORECASE)
        sha_match = re.findall(r'\bsha\d+\b\s*=\s*"([^"]+)"', meta_block, re.IGNORECASE)

        rule_data['md5'] = md5_match.group(1) if md5_match else "0"
        # Join all matched SHA hashes with commas, or return "0" if none found
        rule_data['sha256'] = ','.join(sha_match) if sha_match else "0"

        date_matches = re.findall(r'(date|last_modified|last_updated)\s*=\s*["\']([\d\-\/]+)["\']', meta_block, re.IGNORECASE)
        if date_matches:
        # Use the first match found
            appeared_value = date_matches[0][1]

        rule_data['appeared'] = appeared_value if appeared_value else "0"



        # === STRINGS ===
        strings_match = re.search(r'strings:\s*(.*?)(?=^\s*(meta:|condition:|\}))', rule_body, re.DOTALL | re.IGNORECASE | re.MULTILINE)
        string_lines = []
        hex_patterns = []

        if strings_match:
            strings_block = strings_match.group(1)

            # Plain text strings
            text_strings = re.findall(r'"(.*?)"', strings_block)
            string_lines.extend(text_strings)

            # Hex patterns
            hex_patterns = re.findall(r'\{([^}]+)\}', strings_block)
            if hex_patterns:
                string_lines.extend(hex_patterns)

        
        rule_data['string_lines'] = string_lines
        rule_data['hex_patterns'] = hex_patterns


        # === CONDITION ===
        condition_match = re.search(r'condition:\s*(.*)', rule_body, re.DOTALL | re.IGNORECASE)
        condition_block = condition_match.group(1).strip() if condition_match else ""
        rule_data['condition'] = condition_block

        # Extract filesize expressions
        filesize_matches = re.findall(r'filesize\s*(==|!=|<=|>=|<|>)\s*([0-9]+(?:\.[0-9]+)?\s*(?:[kKmMgGtTpP][bB])?)', condition_block)
        filesize_conditions = [op + value.replace(" ", "") for op, value in filesize_matches]
        rule_data['filesize_conditions'] = filesize_conditions

        hashed_value = re.search(r'"([a-fA-F0-9]{32})"', condition_block)
        rule_data['md5'] = hashed_value.group(1) if hashed_value else "0"
        
        rules_data.append(rule_data)
        
    return rules_data

def parse_yara_rule(file_path):

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        yara_rule = f.readlines()

    # Extract strings, hex patterns, and conditions from the YARA rule
    rules_data = extract_yara_rules(yara_rule)

    # Count extracted features
    featured_rules = []

    for rule in rules_data:
        condition_raw = rule['condition']
        string_lines = rule['string_lines']
        hex_patterns = rule['hex_patterns']
        filesize = rule['filesize_conditions']
        date = rule['appeared'] 
        


        # Split condition into parts (approximate logic statements)
        condition_elements = re.split(r'\band\b|\bor\b|\band\s+not\b|==|!=|>=|<=|<|>|[\n\r]', condition_raw)
        condition_elements = [c.strip() for c in condition_elements if c.strip()]
        

        string_length = 0
        for value in rule['string_lines']:
            string_length +=1
            splitter2(value)

        file_name = os.path.basename(file_path)
        file_base_name = os.path.splitext(file_name)[0]
        if "_" in file_base_name:
            parts = file_base_name.split("_")
        
            # Remove parts 
            cleaned_parts = [
                part for part in parts 
                if not re.search(r'(apt|malw|apt1)', part, re.IGNORECASE)
                and not re.fullmatch(r'[a-fA-F0-9]{6,}', part)
            ]
            
            # Reconstruct the rule name
            file_base_name = "_".join(cleaned_parts)
        else:
            file_base_name 
        


        featured_rules.append({
            
            "sha256": rule["sha256"],
            "md5": rule["md5"],
            "appeared":date,
            "family": file_base_name,
            "string_stats":{'numstrings':string_length},
            "general": {'size': filesize},
            "strings": string_lines,
        })

    return featured_rules



# def load_yara_rules(directory):
#     features = []
#     labels = []
    
#     # Iterate through all files in the directory
#     for root, _, files in os.walk(directory):
#         for file in files:
#             if file.endswith(".yar") or file.endswith(".yara"):
#                 file_path = os.path.join(root, file)

#                 parsed_rules = parse_yara_rule(file_path)
#                 for rule in parsed_rules:
#                     features.append(rule)
#                     labels.append("malware")
    
#     return features, labels

# # Load YARA rules from GitHub repo directory
# # Get the directory of the currently running script
# current_dir = Path(__file__).resolve().parent

# # Define the dataset directory relative to the script location
# yara_repo_path = current_dir /"extracted_yara_files"
# X, labels = load_yara_rules(yara_repo_path)


# # Data Pre-processing
# family = []
# le = LabelEncoder()
# # y_encoded = le.fit_transform(labels)
# y_encoded = [1] * len(labels)

# for rule in X:
#     family.append(rule['family'])
#     y2_encoded = le.fit_transform(family)


# # Upload data to csv file
# df = pd.DataFrame(X)
# df["class"] = y2_encoded
# df["label"] = y_encoded
# df.to_csv("yara_dataset.csv", index=False)
 





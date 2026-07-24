from feature_extractor import extract_features
import json

url = "https://www.google.com"
features = extract_features(url)
print(json.dumps(features, indent=2))
print("\nTotal features extracted:", len(features))

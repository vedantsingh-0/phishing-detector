import pandas as pd

df = pd.read_csv("../data/phishing_dataset.csv")

print("Shape:", df.shape)
print("\nColumns:", list(df.columns))
print("\nFirst 5 rows:")
print(df.head())
print("\nData types:")
print(df.dtypes)

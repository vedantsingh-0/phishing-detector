import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib

# Load data
df = pd.read_csv("../data/phishing_dataset.csv")

# Separate features and label (drop Index too - it's just a row number, not a real feature)
X = df.drop(["class", "Index"], axis=1)
y = df["class"]

print("Feature columns:", list(X.columns))
print("Label distribution:\n", y.value_counts())

# Train-test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# Train model
model = RandomForestClassifier(n_estimators=200, random_state=42)
model.fit(X_train, y_train)

# Evaluate
y_pred = model.predict(X_test)
print("\nAccuracy:", accuracy_score(y_test, y_pred))
print("\nClassification Report:\n", classification_report(y_test, y_pred))
print("Confusion Matrix:\n", confusion_matrix(y_test, y_pred))

# Feature importance
importances = pd.Series(model.feature_importances_, index=X.columns)
print("\nTop 10 important features:\n", importances.sort_values(ascending=False).head(10))

# Save model and feature column order (important for later!)
joblib.dump(model, "phishing_model.pkl")
joblib.dump(list(X.columns), "feature_columns.pkl")
print("\nModel and feature list saved.")

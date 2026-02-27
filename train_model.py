import joblib
import numpy as np
from dataset_py import texts, labels

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline
from sklearn.pipeline import FeatureUnion
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.utils import shuffle

print("Total samples:", len(texts))

# Перемешиваем
texts, labels = shuffle(texts, labels, random_state=42)

# Делим данные
X_train, X_test, y_train, y_test = train_test_split(
    texts,
    labels,
    test_size=0.2,
    stratify=labels,
    random_state=42
)

print("Train size:", len(X_train))
print("Test size:", len(X_test))

# ================= FEATURE ENGINEERING =================

char_vectorizer = TfidfVectorizer(
    analyzer="char",
    ngram_range=(2,6),
    max_features=200000,
    sublinear_tf=True
)

word_vectorizer = TfidfVectorizer(
    analyzer="word",
    ngram_range=(1,2),
    max_features=50000,
    sublinear_tf=True
)

model = Pipeline([
    ("features", FeatureUnion([
        ("char", char_vectorizer),
        ("word", word_vectorizer)
    ])),
    ("clf", LogisticRegression(
        max_iter=5000,
        class_weight="balanced",
        n_jobs=-1
    ))
])

# ================= TRAIN =================

print("Training model...")
model.fit(X_train, y_train)

print("Training complete.")

# ================= EVALUATION =================

y_pred = model.predict(X_test)

print("\n=== Classification Report ===")
report = classification_report(y_test, y_pred)
print(report)

print("\n=== Confusion Matrix ===")
cm = confusion_matrix(y_test, y_pred)
print(cm)

# ================= SAVE =================

joblib.dump(model, "kdefender_ai.pkl")
print("\nModel saved as kdefender_ai.pkl")

with open("training_report.txt", "w", encoding="utf-8") as f:
    f.write("Samples: " + str(len(texts)) + "\n\n")
    f.write(report)
    f.write("\nConfusion Matrix:\n")
    f.write(str(cm))

print("Report saved to training_report.txt")

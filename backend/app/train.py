"""Train the URL model and print evaluation metrics."""
from __future__ import annotations
import argparse
from pathlib import Path
import pandas as pd
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score, classification_report
from .features import extract_features, FEATURE_NAMES
from .model import train_model, label_value


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", type=Path, default=Path(__file__).resolve().parents[1] / "data" / "sample_urls.csv")
    args = parser.parse_args()
    result = train_model(args.data)
    frame = pd.read_csv(args.data)
    x = pd.DataFrame([extract_features(str(url)) for url in frame.url])[FEATURE_NAMES]
    y = frame[next(c for c in ["label", "type", "status"] if c in frame.columns)].map(label_value)
    predictions = result["model"].predict(x)
    probabilities = result["model"].predict_proba(x)[:, 1]
    print(f"rows: {result['rows']}")
    print(f"accuracy: {accuracy_score(y, predictions):.3f}")
    print(f"precision: {precision_score(y, predictions, zero_division=0):.3f}")
    print(f"recall: {recall_score(y, predictions, zero_division=0):.3f}")
    print(f"f1: {f1_score(y, predictions, zero_division=0):.3f}")
    try:
        print(f"roc_auc: {roc_auc_score(y, probabilities):.3f}")
    except ValueError:
        print("roc_auc: unavailable")
    print(classification_report(y, predictions, zero_division=0))


if __name__ == "__main__":
    main()

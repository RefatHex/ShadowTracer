"""MLflow models-from-code (no pickled classes): the pyfunc every incident model is served as.

Input: a DataFrame with exactly features.FEATURE_NAMES columns (features.model_input).
Output: a DataFrame with `score` (0..1) and `reasons` (JSON list of the top contributing features).
With an "estimator" artifact (a joblib'd scikit-learn pipeline with predict_proba) it scores with
it; without one it is the DUMMY model: score = max_level / 15, reasons = ["max_level"] - used to
prove the serving path, never promoted over a baseline. Scores are advisory: no model triggers
any action (docs/ML_FOUNDATION.md).
"""
import json

import mlflow
import numpy as np
import pandas as pd


class IncidentRiskModel(mlflow.pyfunc.PythonModel):
    def load_context(self, context):
        self.estimator = None
        if context and context.artifacts and "estimator" in context.artifacts:
            import joblib
            self.estimator = joblib.load(context.artifacts["estimator"])

    def predict(self, context, model_input: pd.DataFrame, params=None) -> pd.DataFrame:
        X = model_input.astype(float)
        if self.estimator is None:
            score = np.clip(X["max_level"].to_numpy() / 15.0, 0.0, 1.0)
            reasons = [json.dumps(["max_level"])] * len(X)
        else:
            score = self.estimator.predict_proba(X)[:, 1]
            reasons = [json.dumps(r) for r in top_reasons(self.estimator, X)]
        return pd.DataFrame({"score": score, "reasons": reasons})


def top_reasons(estimator, X: pd.DataFrame, k: int = 3) -> list:
    """Linear models: the k largest coef * standardised value; others: the k largest importances present."""
    last = estimator[-1] if hasattr(estimator, "__getitem__") else estimator
    Z = estimator[:-1].transform(X) if hasattr(estimator, "__getitem__") and len(estimator) > 1 else X.to_numpy()
    if hasattr(last, "coef_"):
        contrib = np.asarray(Z) * last.coef_[0]
    else:
        contrib = (np.asarray(Z) != 0) * getattr(last, "feature_importances_", np.zeros(X.shape[1]))
    cols = list(X.columns)
    return [[cols[j] for j in np.argsort(-row)[:k] if row[j] > 0] for row in contrib]


mlflow.models.set_model(IncidentRiskModel())

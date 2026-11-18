"""Phase 7.4 serving pyfunc: the XGBoost historical classifier, served as MLflow models-from-code
(no pickled classes, and the booster itself is loaded from XGBoost's native JSON/UBJ artifact - never
a pickle, so an untrusted model file can't execute code on load).

Input: a DataFrame with exactly features.FEATURE_NAMES columns (features.model_input).
Output per row: `prob` (P(attack), 0..1), `label` ("attack"/"benign" at the stored decision
threshold), and `reasons` (JSON list of plain-language SHAP reasons, top contributors first).
Advisory only - no model triggers any action (docs/ML_FOUNDATION.md).
"""
import json

import mlflow
import numpy as np
import pandas as pd

from shadowtracer_ml import reasons as reason_tmpl
from shadowtracer_ml.features import FEATURE_NAMES


class IncidentClassifierModel(mlflow.pyfunc.PythonModel):
    def load_context(self, context):
        import xgboost as xgb
        import shap
        self.booster = xgb.Booster()
        self.booster.load_model(context.artifacts["model_ubj"])   # native JSON/UBJ, never pickle
        self.explainer = shap.TreeExplainer(self.booster)
        self.threshold = 0.5
        thr = context.artifacts.get("threshold")
        if thr:
            with open(thr) as f:
                self.threshold = float(json.load(f)["threshold"])

    def predict(self, context, model_input: pd.DataFrame, params=None) -> pd.DataFrame:
        import xgboost as xgb
        X = model_input.astype(float)[list(FEATURE_NAMES)]
        prob = self.booster.predict(xgb.DMatrix(X, feature_names=list(FEATURE_NAMES)))
        prob = np.asarray(prob, dtype=float).reshape(-1)
        sv = np.asarray(self.explainer.shap_values(X))
        reasons = [json.dumps(reason_tmpl.top_reasons(list(FEATURE_NAMES), sv[i], k=5))
                   for i in range(len(X))]
        label = ["attack" if p >= self.threshold else "benign" for p in prob]
        # `score` mirrors `prob` so the enrichment worker stores this model the same way as the 7.0
        # risk model; `prob`/`label` carry the 7.4 class + probability.
        return pd.DataFrame({"score": prob, "prob": prob, "label": label, "reasons": reasons})


mlflow.models.set_model(IncidentClassifierModel())

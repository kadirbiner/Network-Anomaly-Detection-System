from fastapi import FastAPI, UploadFile, File, Query
from fastapi.middleware.cors import CORSMiddleware
from typing import Any, Dict, List, Optional
import pandas as pd
import joblib
import os
import uuid

app = FastAPI(
    title="Network Anomaly Detection API",
    description="Machine Learning based network anomaly and attack category detection system",
    version="3.0.0"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MODEL_DIR = "model"
UPLOAD_DIR = "uploads"
os.makedirs(UPLOAD_DIR, exist_ok=True)

BINARY_MODEL_CONFIGS: Dict[str, Dict[str, Any]] = {
    "random_forest": {
        "file": "network_anomaly_rf_package.pkl",
        "display_name": "Random Forest",
        "description": "High accuracy ensemble model for robust anomaly detection.",
        "performance": {
            "accuracy": 0.9769,
            "precision": 0.9847,
            "recall": 0.9731,
            "f1_score": 0.9789
        }
    },
    "svm": {
        "file": "svm_model_package.pkl",
        "display_name": "SVM",
        "description": "Margin-based classifier suitable for structured traffic patterns.",
        "performance": {
            "accuracy": 0.9360,
            "precision": 0.0,
            "recall": 0.0,
            "f1_score": 0.9413
        }
    },
    "xgboost": {
        "file": "xgboost_model_package.pkl",
        "display_name": "XGBoost",
        "description": "Boosted tree model optimized for high-performance detection.",
        "performance": {
            "accuracy": 0.9812,
            "precision": 0.9883,
            "recall": 0.9769,
            "f1_score": 0.9825
        }
    }
}

MULTI_CLASS_CONFIG = {
    "file": "multi_class_attack_model_package.pkl",
    "display_name": "Multi-Class Attack Detector",
    "description": "Predicts the attack category such as Normal, Generic, Exploits, DoS, Fuzzers and Reconnaissance."
}

TOP_FEATURES = [
    {"feature": "ct_dst_src_ltm", "importance": 0.092173},
    {"feature": "ct_state_ttl", "importance": 0.068786},
    {"feature": "sload", "importance": 0.061795},
    {"feature": "rate", "importance": 0.057475},
    {"feature": "ct_srv_dst", "importance": 0.055458},
    {"feature": "sttl", "importance": 0.054799},
    {"feature": "smean", "importance": 0.054389},
    {"feature": "sbytes", "importance": 0.053663},
    {"feature": "ct_dst_sport_ltm", "importance": 0.051047},
    {"feature": "dbytes", "importance": 0.041893}
]

binary_packages: Dict[str, Dict[str, Any]] = {}
multi_package: Optional[Dict[str, Any]] = None


def load_package(path: str) -> Optional[Dict[str, Any]]:
    if not os.path.exists(path):
        return None

    loaded = joblib.load(path)

    if isinstance(loaded, dict):
        return loaded

    return {
        "model": loaded,
        "features": []
    }


def load_all_models() -> None:
    global multi_package

    for key, cfg in BINARY_MODEL_CONFIGS.items():
        path = os.path.join(MODEL_DIR, cfg["file"])
        package = load_package(path)

        if package is not None:
            binary_packages[key] = package

    multi_path = os.path.join(MODEL_DIR, MULTI_CLASS_CONFIG["file"])
    multi_package = load_package(multi_path)


load_all_models()


def calculate_risk_level(attack_ratio: float):
    if attack_ratio < 10:
        return "LOW", 1, "Network traffic appears generally safe."
    if attack_ratio < 30:
        return "MEDIUM", 2, "Anomalous traffic detected — monitor closely."
    if attack_ratio < 60:
        return "HIGH", 3, "High rate of attack traffic detected."
    return "CRITICAL", 4, "Critical level of attack traffic detected."


def get_prediction_label(value: int):
    return "Attack" if int(value) == 1 else "Normal"


def safe_metric(cfg_metrics: Dict[str, Any], pkg_metrics: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    metrics = dict(cfg_metrics)

    if isinstance(pkg_metrics, dict):
        for key in ["accuracy", "precision", "recall", "f1_score"]:
            if key in pkg_metrics:
                try:
                    metrics[key] = round(float(pkg_metrics[key]), 4)
                except Exception:
                    metrics[key] = pkg_metrics[key]

    return metrics


def get_binary_model(model_name: str):
    if model_name not in BINARY_MODEL_CONFIGS:
        raise ValueError(f"Invalid model_name '{model_name}'. Valid options: {list(BINARY_MODEL_CONFIGS.keys())}")

    if model_name not in binary_packages:
        raise FileNotFoundError(
            f"{BINARY_MODEL_CONFIGS[model_name]['file']} was not found or could not be loaded. "
            f"Place it under backend/model/."
        )

    cfg = BINARY_MODEL_CONFIGS[model_name]
    pkg = binary_packages[model_name]

    if "model" not in pkg:
        raise ValueError(f"Model package for {model_name} does not contain a 'model' key.")

    if "features" not in pkg or not pkg["features"]:
        raise ValueError(f"Model package for {model_name} does not contain a valid 'features' list.")

    metrics = safe_metric(cfg["performance"], pkg.get("metrics"))

    return {
        "key": model_name,
        "display_name": cfg["display_name"],
        "description": cfg["description"],
        "model": pkg["model"],
        "features": pkg["features"],
        "scaler": pkg.get("scaler"),
        "metrics": metrics
    }


def prepare_uploaded_file(file: UploadFile) -> str:
    if not file.filename or not file.filename.lower().endswith(".csv"):
        raise ValueError("Please upload a CSV file.")

    file_id = str(uuid.uuid4())
    safe_name = os.path.basename(file.filename)
    file_path = os.path.join(UPLOAD_DIR, f"{file_id}_{safe_name}")

    return file_path


def validate_dataframe(df: pd.DataFrame, features: List[str], model_name: str):
    if len(df) == 0:
        raise ValueError("The uploaded CSV file is empty.")

    missing_columns = [col for col in features if col not in df.columns]

    if missing_columns:
        return {
            "success": False,
            "error": f"CSV is missing required columns for {model_name}.",
            "missing_columns": missing_columns,
            "required_feature_count": len(features),
            "received_columns": list(df.columns)
        }

    return None


@app.get("/")
def home():
    return {
        "message": "Network Anomaly Detection API is running",
        "version": "3.0.0",
        "available_binary_models": list(BINARY_MODEL_CONFIGS.keys()),
        "multi_class_available": multi_package is not None,
        "status": "active"
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
        "binary_models_loaded": {
            key: key in binary_packages for key in BINARY_MODEL_CONFIGS.keys()
        },
        "multi_class_loaded": multi_package is not None,
        "feature_counts": {
            key: len(pkg.get("features", [])) for key, pkg in binary_packages.items()
        }
    }


@app.get("/models")
def list_models():
    models = []

    for key, cfg in BINARY_MODEL_CONFIGS.items():
        pkg = binary_packages.get(key)
        pkg_metrics = pkg.get("metrics") if isinstance(pkg, dict) else None

        models.append({
            "key": key,
            "name": cfg["display_name"],
            "description": cfg["description"],
            "loaded": key in binary_packages,
            "performance": safe_metric(cfg["performance"], pkg_metrics)
        })

    return {
        "binary_models": models,
        "multi_class": {
            "key": "multi_class",
            "name": MULTI_CLASS_CONFIG["display_name"],
            "description": MULTI_CLASS_CONFIG["description"],
            "loaded": multi_package is not None
        }
    }


@app.get("/model-info")
def model_info(model_name: str = Query("random_forest")):
    selected = get_binary_model(model_name)

    return {
        "model_key": selected["key"],
        "model_name": selected["display_name"],
        "description": selected["description"],
        "dataset": "UNSW-NB15",
        "task": "Binary Network Anomaly Detection",
        "target": "label",
        "normal_label": 0,
        "attack_label": 1,
        "feature_count": len(selected["features"]),
        "features": selected["features"],
        "performance": selected["metrics"],
        "top_features": TOP_FEATURES
    }


@app.post("/predict-csv")
async def predict_csv(
    file: UploadFile = File(...),
    model_name: str = Query("random_forest", description="Model key: random_forest, svm, or xgboost")
):
    file_path = ""

    try:
        selected = get_binary_model(model_name)

        file_path = prepare_uploaded_file(file)

        with open(file_path, "wb") as f:
            f.write(await file.read())

        df = pd.read_csv(file_path)
        total_records = len(df)

        validation_error = validate_dataframe(df, selected["features"], selected["display_name"])
        if validation_error:
            return validation_error

        X = df[selected["features"]].copy()

        if selected["scaler"] is not None:
            X_input = selected["scaler"].transform(X)
        else:
            X_input = X

        predictions = selected["model"].predict(X_input)

        if hasattr(selected["model"], "predict_proba"):
            probabilities = selected["model"].predict_proba(X_input)[:, 1]
        else:
            probabilities = [None] * len(predictions)

        result_df = df.copy()
        result_df["prediction"] = predictions
        result_df["prediction_label"] = result_df["prediction"].apply(get_prediction_label)

        if probabilities is not None:
            result_df["attack_probability"] = probabilities

        normal_count = int((predictions == 0).sum())
        attack_count = int((predictions == 1).sum())
        attack_ratio = round((attack_count / total_records) * 100, 2)

        risk_level, severity_score, risk_message = calculate_risk_level(attack_ratio)

        preview_columns = ["prediction", "prediction_label"]
        if "attack_probability" in result_df.columns:
            preview_columns.append("attack_probability")

        preview = result_df[preview_columns].head(20).to_dict(orient="records")

        return {
            "success": True,
            "file_name": file.filename,
            "task": "Binary Network Anomaly Detection",
            "total_records": total_records,
            "normal_count": normal_count,
            "attack_count": attack_count,
            "attack_ratio": attack_ratio,
            "risk_level": risk_level,
            "severity_score": severity_score,
            "risk_message": risk_message,
            "model_name": selected["display_name"],
            "model_key": selected["key"],
            "model_description": selected["description"],
            "model_metrics": selected["metrics"],
            "top_features": TOP_FEATURES,
            "preview": preview
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

    finally:
        if file_path and os.path.exists(file_path):
            try:
                os.remove(file_path)
            except Exception:
                pass


@app.post("/predict-attack-category")
async def predict_attack_category(file: UploadFile = File(...)):
    file_path = ""

    try:
        if multi_package is None:
            return {
                "success": False,
                "error": "Multi-class model package was not found. Place multi_class_attack_model_package.pkl under backend/model/."
            }

        if "model" not in multi_package:
            return {
                "success": False,
                "error": "Multi-class package does not contain a 'model' key."
            }

        multi_features = multi_package.get("features", [])
        if not multi_features:
            return {
                "success": False,
                "error": "Multi-class package does not contain a valid 'features' list."
            }

        file_path = prepare_uploaded_file(file)

        with open(file_path, "wb") as f:
            f.write(await file.read())

        df = pd.read_csv(file_path)
        total_records = len(df)

        validation_error = validate_dataframe(df, multi_features, "multi-class attack detector")
        if validation_error:
            return validation_error

        X = df[multi_features].copy()

        feature_encoders = multi_package.get("feature_encoders", {})

        for col, encoder in feature_encoders.items():
            if col in X.columns:
                X[col] = X[col].astype(str)
                known_classes = set(encoder.classes_)

                fallback_value = encoder.classes_[0]
                X[col] = X[col].apply(lambda value: value if value in known_classes else fallback_value)
                X[col] = encoder.transform(X[col])

        model = multi_package["model"]
        target_encoder = multi_package.get("target_encoder")

        predictions_encoded = model.predict(X)

        if target_encoder is not None:
            predictions = target_encoder.inverse_transform(predictions_encoded)
        else:
            predictions = predictions_encoded

        if hasattr(model, "predict_proba"):
            probabilities = model.predict_proba(X)
            confidence = probabilities.max(axis=1)
        else:
            confidence = [None] * len(predictions)

        result_df = df.copy()
        result_df["attack_category_prediction"] = predictions
        result_df["confidence"] = confidence

        category_counts = result_df["attack_category_prediction"].value_counts().to_dict()

        category_distribution = [
            {
                "category": str(category),
                "count": int(count),
                "percentage": round((count / total_records) * 100, 2)
            }
            for category, count in category_counts.items()
        ]

        category_distribution = sorted(
            category_distribution,
            key=lambda item: item["count"],
            reverse=True
        )

        preview = result_df[["attack_category_prediction", "confidence"]].head(20).to_dict(orient="records")

        attack_like_count = int(total_records - category_counts.get("Normal", 0))
        attack_ratio = round((attack_like_count / total_records) * 100, 2)
        risk_level, severity_score, risk_message = calculate_risk_level(attack_ratio)

        metrics = multi_package.get("metrics", {})

        return {
            "success": True,
            "file_name": file.filename,
            "task": "Multi-Class Attack Category Detection",
            "model_name": MULTI_CLASS_CONFIG["display_name"],
            "model_key": "multi_class",
            "model_description": MULTI_CLASS_CONFIG["description"],
            "model_metrics": metrics,
            "total_records": total_records,
            "attack_like_count": attack_like_count,
            "attack_ratio": attack_ratio,
            "risk_level": risk_level,
            "severity_score": severity_score,
            "risk_message": risk_message,
            "detected_categories": category_distribution,
            "preview": preview
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

    finally:
        if file_path and os.path.exists(file_path):
            try:
                os.remove(file_path)
            except Exception:
                pass

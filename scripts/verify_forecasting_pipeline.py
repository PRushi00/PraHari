"""
Comprehensive Empirical Verification of the PraHari Threat Forecasting Pipeline.

Analyzes:
1. Dataset & Label Distribution (positive incident count vs benign)
2. Window Feature Extraction & Temporal Sliding Windows
3. Overlapping-Window Autocorrelation & Leakage Risk Analysis
4. Strict Temporal Train/Test Splitting (Chronological, No Shuffling)
5. Comparative Benchmark Evaluations:
   - Majority Class Baseline
   - Heuristic Threshold Baseline
   - Calibrated Logistic Regression
   - Random Forest Classifier
6. Metrics: Accuracy, Precision, Recall, F1, PR-AUC, ROC-AUC, Brier Score Loss, Confusion Matrix
7. Probability Calibration Analysis
"""
import sys
from pathlib import Path
import numpy as np

# Add backend to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "backend"))

from app.adapters.csv_import import CsvImportAdapter
from app.models.feature_extractor import WindowFeatureExtractor, FEATURE_NAMES
from app.models.forecaster import (
    BaselineConstantModel,
    BaselineThresholdModel,
    InsufficientEvaluationDataError,
    ThreatForecastingPipeline,
)
from app.schemas.events import DataCategory

def run_empirical_forecasting_audit():
    fixture_path = Path(__file__).resolve().parent.parent / "backend" / "tests" / "fixtures" / "sample_flows.csv"
    assert fixture_path.exists(), f"Fixture missing: {fixture_path}"

    print("==================================================================")
    print("  PraHari — Empirical Forecasting Pipeline Verification Audit")
    print("==================================================================\n")

    # 1. Dataset & Label Inspection
    adapter = CsvImportAdapter()
    events, summary = adapter.import_file(fixture_path, source_id="empirical_audit_src", data_category=DataCategory.HISTORICAL_IMPORT)
    
    print(f"[1. DATASET & GROUND TRUTH LABELS]")
    print(f"Total CSV records:   {summary.total_records}")
    print(f"Accepted flows:      {len(events)} (valid schema & normalized)")
    print(f"Rejected records:    {summary.rejected_records} (malformed synthetic test cases)")
    
    labels = [e.label or "unlabeled" for e in events]
    benign_count = sum(1 for l in labels if l.lower() == "benign")
    attack_count = sum(1 for l in labels if l.lower() != "benign")
    
    print(f"Ground-truth Benign: {benign_count} ({benign_count/len(events)*100:.1f}%)")
    print(f"Ground-truth Attack: {attack_count} ({attack_count/len(events)*100:.1f}%)")
    attack_types = set(l for l in labels if l.lower() != "benign")
    print(f"Attack Categories:   {', '.join(attack_types)}")
    print()

    # 2. Window Construction & Leakage Audit
    extractor = WindowFeatureExtractor(
        window_size_seconds=60.0,
        lead_time_seconds=30.0,
        prediction_horizon_seconds=60.0,
    )
    
    X, y, timestamps = extractor.build_dataset_instances(events, step_seconds=15.0)
    print(f"[2. CAUSAL WINDOW FORMULATION & LEAKAGE CONTROLS]")
    print(f"Observation Window (W):   60.0 seconds (retrospective features [t - W, t])")
    print(f"Lead Time Buffer:         30.0 seconds [t, t + lead_time]")
    print(f"Prediction Horizon (H):   60.0 seconds [t + lead_time, t + lead_time + H]")
    print(f"Step Stride:              15.0 seconds")
    print(f"Extracted Instances (N):  {len(y)} windows")
    print(f"Positive Incident Windows (y=1): {int(np.sum(y))} ({np.mean(y)*100:.1f}%)")
    print(f"Negative Normal Windows (y=0):   {len(y) - int(np.sum(y))} ({(1-np.mean(y))*100:.1f}%)")
    print(f"Features Extracted (D):          {X.shape[1]} causal metrics ({', '.join(FEATURE_NAMES[:4])}...)")
    
    # Disclose the configuration actually used (short spans force rescaling).
    wr = extractor.last_windowing_report
    if wr is not None and not wr.uses_nominal_config:
        print()
        print("   [CONFIGURATION NOTICE] The nominal W/L/H/S above were NOT used:")
        for note in wr.notes:
            print(f"   - {note}")
        print(f"   Effective: W={wr.effective_window_seconds}s L={wr.effective_lead_seconds}s "
              f"H={wr.effective_horizon_seconds}s S={wr.effective_stride_seconds}s")

    # Overlapping window analysis
    print("\n   [LEAKAGE RISK ANALYSIS - OVERLAPPING WINDOWS]:")
    print("   Sliding a 60s observation window by 15s makes adjacent feature vectors")
    print("   share 45s of telemetry. Worse, a window's LABEL describes [t+30s, t+90s]")
    print("   - a period that later windows take as INPUT. So a bare index split leaks")
    print("   twice: test windows re-observe training telemetry, and training labels")
    print("   describe data that test windows use as features.")
    print("   PraHari DEFENSE: chronological split WITH a train-side purge of")
    print("   ceil((W+L+H)/S) windows. Contaminated boundary windows are dropped from")
    print("   training; the holdout is preserved. Instances are never reassigned across")
    print("   the boundary, and evaluation is REFUSED when no honest split exists.")
    print()

    # 3. Temporal Train / Test Split
    train_ratio = 0.7
    n_train = int(len(y) * train_ratio)
    X_train, y_train = X[:n_train], y[:n_train]
    X_test, y_test = X[n_train:], y[n_train:]
    
    print(f"[3. NAIVE SPLIT (shown only to illustrate what is NOT used)]")
    print(f"A bare 70/30 index split would give {n_train} train / {len(y_test)} test windows")
    print(f"with train positives {int(np.sum(y_train))}/{len(y_train)} and test positives "
          f"{int(np.sum(y_test))}/{len(y_test)}.")
    print("This split is CONTAMINATED at the boundary and is not what PraHari evaluates on.")
    print()

    # 4. Pipeline Execution & Model Benchmarking
    pipeline = ThreatForecastingPipeline(
        window_size_seconds=60.0,
        lead_time_seconds=30.0,
        prediction_horizon_seconds=60.0,
    )
    try:
        metrics_map = pipeline.train_and_evaluate_all(events, train_ratio=train_ratio)
    except InsufficientEvaluationDataError as exc:
        rep = exc.split_report
        print("[4. EVALUATION REFUSED - NO LEAKAGE-FREE SPLIT EXISTS]")
        print()
        print(f"  {exc}")
        print()
        if rep is not None:
            print("  Split evidence:")
            print(f"    total windows          : {rep.total_instances}")
            print(f"    purged (contaminated)  : {rep.purged_instances} "
                  f"({rep.embargo_windows} windows = {rep.embargo_seconds}s)")
            print(f"    leakage-free training  : {rep.train_instances} "
                  f"(positives {rep.train_positive}, negatives {rep.train_negative})")
            print(f"    holdout                : {rep.test_instances} "
                  f"(positives {rep.test_positive}, negatives {rep.test_negative})")
        print()
        print("  This is the correct outcome for this fixture, not a failure of the")
        print("  pipeline. The dataset spans ~5 minutes with attacks concentrated early;")
        print("  it cannot support training on the past and evaluating on strictly later")
        print("  data once overlapping windows are purged.")
        print()
        print("  No metrics are reported, because any number produced here would come")
        print("  from a contaminated split. To obtain a defensible evaluation, supply")
        print("  telemetry spanning more time with labelled attack and benign activity")
        print("  in BOTH the earlier and later periods.")
        return

    rep = pipeline.last_split_report
    if rep is not None:
        print("[3b. PURGED CHRONOLOGICAL SPLIT ACTUALLY USED]")
        print(f"  training windows : {rep.train_instances} "
              f"(positives {rep.train_positive}, negatives {rep.train_negative})")
        print(f"  purged           : {rep.purged_instances} boundary windows "
              f"({rep.embargo_seconds}s)")
        print(f"  holdout windows  : {rep.test_instances} "
              f"(positives {rep.test_positive}, negatives {rep.test_negative})")
        print(f"  train ends       : {rep.train_end_timestamp}")
        print(f"  test begins      : {rep.test_start_timestamp}")
        print()

    print(f"[4. EMPIRICAL MODEL BENCHMARK RESULTS]")
    print(f"{'Model Name':<28} | {'Accuracy':<8} | {'Precision':<9} | {'Recall':<6} | {'F1':<6} | {'PR-AUC':<7} | {'ROC-AUC':<7} | {'Brier':<6}")
    print("-" * 88)
    
    for model_id, m in metrics_map.items():
        pr_str = f"{m.pr_auc:.3f}" if m.pr_auc is not None else "N/A"
        roc_str = f"{m.roc_auc:.3f}" if m.roc_auc is not None else "N/A"
        brier_str = f"{m.brier_score:.3f}" if m.brier_score is not None else "N/A"
        print(f"{m.model_name:<28} | {m.accuracy*100:>7.1f}% | {m.precision*100:>8.1f}% | {m.recall*100:>5.1f}% | {m.f1:>6.3f} | {pr_str:>7} | {roc_str:>7} | {brier_str:>6}")
        
    print()
    print("[5. CALIBRATION & SCIENTIFIC RIGOR EVIDENCE]")
    rf_m = metrics_map.get("random_forest_forecaster")
    lr_m = metrics_map.get("logistic_regression")
    print(f"- Random Forest Brier Score Loss: {rf_m.brier_score if rf_m else 'N/A'} (Lower is better, 0.0 is perfect calibration)")
    print(f"- Logistic Regression Brier Score: {lr_m.brier_score if lr_m else 'N/A'}")
    print(f"- Random Forest Confusion Matrix (TN, FP / FN, TP): {rf_m.confusion_matrix if rf_m else 'N/A'}")
    print(f"- False Positive Rate on Test Future: {rf_m.false_positive_rate*100:.1f}%")
    
    print("\n[6. TOP FEATURE IMPORTANCES (Random Forest)]")
    if rf_m and rf_m.feature_importance:
        sorted_feats = sorted(rf_m.feature_importance.items(), key=lambda x: x[1], reverse=True)
        for f_name, imp in sorted_feats[:5]:
            print(f"  • {f_name:<22}: {imp*100:.1f}% contribution weight")
            
    print("\n[7. METRIC INTERPRETABILITY]")
    any_uninterpretable = False
    for model_id, m in metrics_map.items():
        if not m.metrics_interpretable:
            any_uninterpretable = True
            print(f"  {m.model_name}: NOT INTERPRETABLE "
                  f"(test positives={m.test_positive_count}, negatives={m.test_negative_count})")
            for w in m.interpretation_warnings:
                print(f"    - {w}")
    if not any_uninterpretable:
        print("  All reported metrics were computed on a holdout containing both")
        print("  positive and negative windows with adequate sample size.")

    print("\n[SCIENTIFIC STATUS]")
    print("Metrics above come from a purged chronological holdout. They are an honest")
    print("measurement of this dataset, not a claim of general forecasting ability.")
    print("Demonstrating predictive effectiveness requires labelled incident data across")
    print("multiple independent time periods or scenarios, which this fixture does not provide.")

if __name__ == "__main__":
    run_empirical_forecasting_audit()

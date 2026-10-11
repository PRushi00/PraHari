"""
Unit tests for Causal Feature Extractor and Threat Forecasting Pipeline.
"""

from datetime import datetime, timezone, timedelta
import pytest
import numpy as np

from app.schemas.events import NormalizedEvent, EventType, DataCategory, LabelProvenance
from app.models.feature_extractor import WindowFeatureExtractor, FEATURE_NAMES
from app.models.forecaster import ThreatForecastingPipeline


def test_window_feature_extractor():
    extractor = WindowFeatureExtractor(window_size_seconds=60.0)
    base_time = datetime(2026, 2, 15, 10, 0, 0, tzinfo=timezone.utc)

    events = [
        NormalizedEvent(
            source_id="test_flow",
            observed_at=base_time + timedelta(seconds=i * 5),
            event_type=EventType.NETWORK_FLOW,
            src_ip="192.168.1.10",
            dst_ip="10.0.0.1",
            src_port=40000 + i,
            dst_port=443,
            protocol="TCP",
            duration=1000.0,
            packets=10,
            bytes_total=1500,
            label="Benign",
        )
        for i in range(10)
    ]

    features = extractor.extract_features_from_window(events, window_duration=60.0)
    assert len(features) == len(FEATURE_NAMES)
    assert features[0] == 10.0  # flow_count
    assert features[1] == 1.0   # distinct_src_ips
    assert features[2] == 1.0   # distinct_dst_ips
    assert features[4] == 15000.0  # total_bytes
    assert features[8] == 1.0   # tcp_ratio


def test_threat_forecasting_pipeline():
    pipeline = ThreatForecastingPipeline(
        window_size_seconds=30.0,
        lead_time_seconds=10.0,
        prediction_horizon_seconds=30.0,
    )

    base_time = datetime(2026, 2, 15, 8, 0, 0, tzinfo=timezone.utc)
    events: list[NormalizedEvent] = []

    # Generate 60 flows spanning ~300 seconds
    for i in range(60):
        t = base_time + timedelta(seconds=i * 5)
        # Attacks concentrated in second half
        is_attack = i >= 40
        events.append(
            NormalizedEvent(
                source_id="sensor_forecast_test",
                observed_at=t,
                event_type=EventType.NETWORK_FLOW,
                src_ip="192.168.1.50" if not is_attack else "198.51.100.22",
                dst_ip="10.0.0.1",
                src_port=50000 + i,
                dst_port=443 if not is_attack else 22,
                protocol="TCP",
                duration=500.0 if not is_attack else 50000.0,
                packets=5 if not is_attack else 25,
                bytes_total=500 if not is_attack else 12000,
                label="Benign" if not is_attack else "SSH-BruteForce",
                label_provenance=LabelProvenance.DATASET_GROUND_TRUTH,
            )
        )

    metrics = pipeline.train_and_evaluate_all(events, train_ratio=0.7)

    # Confirm models were trained and evaluated
    assert "baseline_constant" in metrics
    assert "baseline_threshold" in metrics
    assert "logistic_regression" in metrics
    assert "random_forest_forecaster" in metrics

    rf_metric = metrics["random_forest_forecaster"]
    assert 0.0 <= rf_metric.accuracy <= 1.0
    assert 0.0 <= rf_metric.precision <= 1.0
    assert 0.0 <= rf_metric.recall <= 1.0
    assert 0.0 <= rf_metric.f1 <= 1.0

    # Test live prediction on recent window
    pred = pipeline.predict_recent_window(events[-15:], model_id="random_forest_forecaster")
    assert 0.0 <= pred.propensity_score <= 1.0
    assert isinstance(pred.predicted_incident, bool)
    assert len(pred.top_contributing_features) > 0

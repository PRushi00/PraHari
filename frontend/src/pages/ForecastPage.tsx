import React, { useState, useEffect } from "react";
import {
  TrendingUp,
  Cpu,
  BarChart,
  Play,
  AlertTriangle,
  Zap,
} from "lucide-react";
import { api } from "../services/api";
import { ModelMetrics, PredictionResult, TelemetrySource } from "../types";

export const ForecastPage: React.FC = () => {
  const [models, setModels] = useState<Record<string, ModelMetrics>>({});
  const [sources, setSources] = useState<TelemetrySource[]>([]);
  const [selectedSource, setSelectedSource] = useState<string>("");
  const [training, setTraining] = useState(false);
  const [predicting, setPredicting] = useState(false);
  const [prediction, setPrediction] = useState<PredictionResult | null>(null);
  const [activeModelId, setActiveModelId] = useState<string>("random_forest_forecaster");
  const [threshold, setThreshold] = useState<number>(0.5);
  const [trainRatio, setTrainRatio] = useState<number>(0.7);
  const [error, setError] = useState<string | null>(null);

  const fetchInitialData = async () => {
    try {
      const [srcData, modelData] = await Promise.all([
        api.getSources(),
        api.getForecastingModels().catch(() => ({})),
      ]);
      setSources(srcData);
      setModels(modelData || {});
    } catch (err: any) {
      console.error(err);
    }
  };

  useEffect(() => {
    fetchInitialData();
  }, []);

  const handleTrainModels = async () => {
    setTraining(true);
    setError(null);
    try {
      const res = await api.trainForecastingModels({
        source_id: selectedSource || undefined,
        max_events: 10000,
        train_ratio: trainRatio,
      });
      setModels(res);
      // Auto-run prediction with newly trained model
      handlePredict(activeModelId);
    } catch (err: any) {
      setError(err.message || "Failed to train forecasting models");
    } finally {
      setTraining(false);
    }
  };

  const handlePredict = async (modelIdToUse?: string) => {
    setPredicting(true);
    setError(null);
    try {
      const res = await api.predictIncidentPropensity({
        source_id: selectedSource || undefined,
        model_id: modelIdToUse || activeModelId,
        threshold: threshold,
      });
      setPrediction(res);
    } catch (err: any) {
      setError(err.message || "Prediction failed");
    } finally {
      setPredicting(false);
    }
  };

  const modelKeys = Object.keys(models);

  return (
    <div className="page-container">
      {/* Page Header */}
      <div className="page-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: "1rem" }}>
        <div>
          <h1 className="page-title">Threat Forecasting & Assurance</h1>
          <p className="page-subtitle">
            Causal window feature engineering and benchmarked machine learning models predicting incident propensity.
          </p>
        </div>
        <div style={{ display: "flex", gap: "0.75rem", alignItems: "center" }}>
          <select
            className="form-select"
            value={trainRatio}
            onChange={(e) => setTrainRatio(parseFloat(e.target.value))}
            style={{ width: "130px" }}
          >
            <option value={0.7}>70/30 Split</option>
            <option value={0.8}>80/20 Split</option>
            <option value={0.6}>60/40 Split</option>
          </select>
          <select
            className="form-select"
            value={selectedSource}
            onChange={(e) => setSelectedSource(e.target.value)}
            style={{ width: "200px" }}
          >
            <option value="">All Telemetry Sources</option>
            {sources.map((s) => (
              <option key={s.source_id} value={s.source_id}>
                {s.name} ({s.event_count} flows)
              </option>
            ))}
          </select>
          <button
            className="btn btn-primary"
            onClick={handleTrainModels}
            disabled={training}
          >
            <Cpu size={15} className={training ? "spin-icon" : ""} />
            {training ? "Training Models..." : "Train Model Benchmark"}
          </button>
        </div>
      </div>

      {error && (
        <div className="glass-panel" style={{ padding: "1rem", marginBottom: "1.5rem", borderLeft: "4px solid var(--accent-rose)", color: "#fca5a5" }}>
          <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
            <AlertTriangle size={18} />
            <span>{error}</span>
          </div>
        </div>
      )}

      {/* Model Benchmark Comparative Table */}
      <div className="glass-panel" style={{ padding: "1.75rem", marginBottom: "1.5rem" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1.25rem", flexWrap: "wrap", gap: "1rem" }}>
          <div>
            <h2 style={{ fontSize: "1.1rem", fontWeight: 600, display: "flex", alignItems: "center", gap: "0.5rem" }}>
              <BarChart size={20} style={{ color: "var(--accent-cyan)" }} />
              Competitive Model Benchmarking (Temporal Evaluation)
            </h2>
            <p style={{ fontSize: "0.8rem", color: "var(--text-dim)", marginTop: "0.2rem" }}>
              Strict chronological past-train / future-test split. Baselines vs Logistic Regression vs Random Forest.
            </p>
          </div>
          {modelKeys.length > 0 && (
            <span className="badge" style={{ background: "rgba(6, 182, 212, 0.15)", color: "var(--accent-cyan)" }}>
              {modelKeys.length} Models Evaluated
            </span>
          )}
        </div>

        {modelKeys.length === 0 ? (
          <div style={{ padding: "2.5rem", textAlign: "center", color: "var(--text-muted)" }}>
            <Cpu size={36} style={{ color: "var(--accent-cyan)", margin: "0 auto 1rem auto" }} />
            <p>No models trained yet on current telemetry.</p>
            <button className="btn btn-primary" onClick={handleTrainModels} style={{ marginTop: "1rem" }} disabled={training}>
              Run Initial Training
            </button>
          </div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table className="data-table" style={{ width: "100%", textAlign: "left" }}>
              <thead>
                <tr>
                  <th>Model</th>
                  <th>Type</th>
                  <th>Precision</th>
                  <th>Recall</th>
                  <th>F1 Score</th>
                  <th>PR-AUC</th>
                  <th>ROC-AUC</th>
                  <th>Brier Score</th>
                  <th>FPR</th>
                  <th>Train/Test</th>
                </tr>
              </thead>
              <tbody>
                {modelKeys.map((k) => {
                  const m = models[k];
                  const isBest = k === "random_forest_forecaster";
                  return (
                    <tr
                      key={k}
                      style={{
                        background: activeModelId === k ? "rgba(6, 182, 212, 0.08)" : undefined,
                        cursor: "pointer",
                      }}
                      onClick={() => {
                        setActiveModelId(k);
                        handlePredict(k);
                      }}
                    >
                      <td style={{ fontWeight: 600 }}>
                        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                          {activeModelId === k && <span style={{ width: 6, height: 6, borderRadius: "50%", background: "var(--accent-cyan)" }} />}
                          <span>{m.model_name}</span>
                          {isBest && (
                            <span className="badge" style={{ fontSize: "0.65rem", background: "rgba(16, 185, 129, 0.2)", color: "#10b981" }}>
                              Best ML
                            </span>
                          )}
                        </div>
                      </td>
                      <td style={{ fontSize: "0.8rem", color: "var(--text-dim)" }}>{m.model_type}</td>
                      <td>{(m.precision * 100).toFixed(1)}%</td>
                      <td>{(m.recall * 100).toFixed(1)}%</td>
                      <td style={{ fontWeight: 600, color: "var(--accent-cyan)" }}>{(m.f1_score * 100).toFixed(1)}%</td>
                      <td>{m.pr_auc != null ? m.pr_auc.toFixed(3) : "—"}</td>
                      <td>{m.roc_auc != null ? m.roc_auc.toFixed(3) : "—"}</td>
                      <td>{m.brier_score != null ? m.brier_score.toFixed(3) : "—"}</td>
                      <td style={{ color: m.false_positive_rate > 0.2 ? "#f43f5e" : "#10b981" }}>
                        {(m.false_positive_rate * 100).toFixed(1)}%
                      </td>
                      <td style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>
                        {m.train_instances} / {m.test_instances}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Live Threat Propensity Scoring & Feature Attribution */}
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(360px, 1fr))", gap: "1.5rem" }}>
        {/* Scoring Controls & Gauge */}
        <div className="glass-panel" style={{ padding: "1.75rem" }}>
          <h2 style={{ fontSize: "1.1rem", fontWeight: 600, marginBottom: "1rem", display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <Zap size={20} style={{ color: "var(--accent-amber)" }} />
            Threat Propensity Scorer
          </h2>

          <div style={{ marginBottom: "1.25rem" }}>
            <label style={{ fontSize: "0.8rem", color: "var(--text-muted)", display: "block", marginBottom: "0.35rem" }}>
              Active Inference Model
            </label>
            <select
              className="form-select"
              value={activeModelId}
              onChange={(e) => {
                setActiveModelId(e.target.value);
                handlePredict(e.target.value);
              }}
              style={{ width: "100%" }}
            >
              {modelKeys.map((k) => (
                <option key={k} value={k}>
                  {models[k]?.model_name || k}
                </option>
              ))}
            </select>
          </div>

          <div style={{ marginBottom: "1.5rem" }}>
            <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.8rem", color: "var(--text-muted)", marginBottom: "0.35rem" }}>
              <span>Decision Threshold</span>
              <span style={{ fontWeight: 600, color: "var(--accent-cyan)" }}>{threshold.toFixed(2)}</span>
            </div>
            <input
              type="range"
              min="0.1"
              max="0.9"
              step="0.05"
              value={threshold}
              onChange={(e) => setThreshold(parseFloat(e.target.value))}
              style={{ width: "100%", accentColor: "var(--accent-cyan)" }}
            />
          </div>

          <button
            className="btn btn-primary"
            onClick={() => handlePredict(activeModelId)}
            disabled={predicting || modelKeys.length === 0}
            style={{ width: "100%", justifyContent: "center" }}
          >
            <Play size={16} className={predicting ? "spin-icon" : ""} />
            {predicting ? "Scoring Horizon..." : "Score Future Horizon"}
          </button>

          {prediction && (
            <div style={{ marginTop: "1.5rem", padding: "1.25rem", borderRadius: "var(--radius-md)", background: prediction.predicted_incident ? "rgba(244, 63, 94, 0.1)" : "rgba(16, 185, 129, 0.1)", border: `1px solid ${prediction.predicted_incident ? "var(--accent-rose)" : "#10b981"}` }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                <span style={{ fontSize: "0.85rem", fontWeight: 600, color: prediction.predicted_incident ? "#f43f5e" : "#10b981" }}>
                  {prediction.predicted_incident ? "PREDICTED INCIDENT IMMINENT" : "BENIGN TELEMETRY FORECAST"}
                </span>
                <span style={{ fontSize: "1.25rem", fontWeight: 800, color: prediction.predicted_incident ? "#f43f5e" : "#10b981" }}>
                  {(prediction.propensity_score * 100).toFixed(1)}%
                </span>
              </div>
              <div style={{ width: "100%", height: 8, background: "rgba(255,255,255,0.1)", borderRadius: 4, marginTop: "0.75rem", overflow: "hidden" }}>
                <div
                  style={{
                    width: `${prediction.propensity_score * 100}%`,
                    height: "100%",
                    background: prediction.predicted_incident ? "var(--accent-rose)" : "#10b981",
                    transition: "width 0.4s ease",
                  }}
                />
              </div>
              <div style={{ fontSize: "0.75rem", color: "var(--text-dim)", marginTop: "0.5rem" }}>
                Lead Time: {prediction.lead_time_seconds}s • Horizon: {prediction.horizon_seconds}s • Model: {prediction.model_name}
              </div>
            </div>
          )}
        </div>

        {/* Feature Impact Attribution */}
        <div className="glass-panel" style={{ padding: "1.75rem" }}>
          <h2 style={{ fontSize: "1.1rem", fontWeight: 600, marginBottom: "0.5rem", display: "flex", alignItems: "center", gap: "0.5rem" }}>
            <TrendingUp size={20} style={{ color: "var(--accent-cyan)" }} />
            Feature Attribution & Telemetry Drivers
          </h2>
          <p style={{ fontSize: "0.8rem", color: "var(--text-dim)", marginBottom: "1.25rem" }}>
            Top retrospective causal signals influencing future incident propensity.
          </p>

          {!prediction || prediction.top_contributing_features.length === 0 ? (
            <div style={{ padding: "2rem", textAlign: "center", color: "var(--text-muted)" }}>
              <p>Execute propensity scoring to view feature attribution.</p>
            </div>
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: "0.85rem" }}>
              {prediction.top_contributing_features.map((feat, idx) => {
                const maxVal = Math.max(...prediction.top_contributing_features.map((f) => f.contribution), 0.01);
                const pct = Math.min(100, Math.max(10, (feat.contribution / maxVal) * 100));
                return (
                  <div key={idx}>
                    <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.8rem", marginBottom: "0.25rem" }}>
                      <span style={{ fontWeight: 600, color: "var(--text-main)" }}>{feat.feature}</span>
                      <span style={{ color: "var(--text-dim)" }}>
                        val: <code style={{ color: "var(--accent-cyan)" }}>{feat.value.toFixed(1)}</code> • impact: {feat.contribution.toFixed(3)}
                      </span>
                    </div>
                    <div style={{ width: "100%", height: 6, background: "rgba(255,255,255,0.06)", borderRadius: 3, overflow: "hidden" }}>
                      <div
                        style={{
                          width: `${pct}%`,
                          height: "100%",
                          background: "linear-gradient(90deg, var(--accent-cyan), var(--accent-blue))",
                        }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

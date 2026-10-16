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

import { fmtFixed, fmtPercent, isNum, safeSeries } from "../utils/format";
import { bestModelId } from "../utils/models";
export const ForecastPage: React.FC = () => {
  const [models, setModels] = useState<Record<string, ModelMetrics>>({});
  const [sources, setSources] = useState<TelemetrySource[]>([]);
  const [selectedSource, setSelectedSource] = useState<string>("");
  const [training, setTraining] = useState(false);
  const [predicting, setPredicting] = useState(false);
  const [prediction, setPrediction] = useState<PredictionResult | null>(null);
  const [activeModelId, setActiveModelId] = useState<string>("random_forest_forecaster");

  // Best = highest measured PR-AUC among non-baseline models.
  const best = React.useMemo(() => bestModelId(models), [models]);
  const [threshold, setThreshold] = useState<number>(0.5);
  const [trainRatio, setTrainRatio] = useState<number>(0.7);
  const [error, setError] = useState<string | null>(null);
  const [readiness, setReadiness] = useState<import("../types").ReadinessReport | null>(null);
  const [integrity, setIntegrity] = useState<import("../types").SplitIntegrityReport | null>(null);
  const [blocked, setBlocked] = useState<any | null>(null);

  const fetchInitialData = async () => {
    try {
      const [srcData, modelData, ready, integ] = await Promise.all([
        api.getSources(),
        api.getForecastingModels().catch(() => ({})),
        api.getForecastReadiness().catch(() => null),
        api.getForecastIntegrity().catch(() => null),
      ]);
      setSources(srcData);
      setModels(modelData || {});
      setReadiness(ready);
      setIntegrity(integ);
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
    setBlocked(null);
    try {
      const res = await api.trainForecastingModels({
        source_id: selectedSource || undefined,
        max_events: 10000,
        train_ratio: trainRatio,
      });
      setModels(res);
      handlePredict(activeModelId);
    } catch (err: any) {
      // The backend refuses with a structured explanation; show it rather
      // than a bare failure message.
      const parsed = parseBlocked(err);
      if (parsed) setBlocked(parsed);
      else setError(err.message || "Failed to train forecasting models");
    } finally {
      setTraining(false);
      fetchInitialData();
    }
  };

  /**
   * The API returns a JSON object as `detail` when the research gate or the
   * split-integrity guard refuses an operation.
   */
  const parseBlocked = (err: any): any | null => {
    try {
      const parsedDetail = JSON.parse(err.message);
      if (parsedDetail && typeof parsedDetail === "object" && parsedDetail.error) {
        return parsedDetail;
      }
    } catch {
      // not a JSON detail
    }
    return null;
  };

  const handlePredict = async (modelIdToUse?: string) => {
    setPredicting(true);
    setError(null);
    setBlocked(null);
    try {
      const res = await api.predictIncidentPropensity({
        source_id: selectedSource || undefined,
        model_id: modelIdToUse || activeModelId,
        threshold: threshold,
      });
      setPrediction(res);
    } catch (err: any) {
      const parsed = parseBlocked(err);
      if (parsed) setBlocked(parsed);
      else setError(err.message || "Prediction failed");
    } finally {
      setPredicting(false);
    }
  };

  const modelKeys = Object.keys(models);

  const READINESS_LABEL: Record<string, string> = {
    insufficient_data: "Insufficient data",
    missing_or_invalid_labels: "Missing or invalid labels",
    invalid_evaluation_conditions: "No evaluated model yet",
    inadequate_class_representation: "Inadequate class representation",
    evaluated_performance_inadequate: "Evaluated — performance inadequate",
    trained_not_validated: "Trained but not validated",
    validated_with_documented_conditions: "Validated under documented conditions",
  };

  const readinessPanel = readiness && (
    <div className="glass-panel" style={{ padding: "1.5rem", marginBottom: "1.5rem" }}>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: "0.75rem",
        }}
      >
        <h3 style={{ margin: 0, fontSize: "1rem", fontWeight: 600 }}>Research Readiness</h3>
        <span
          className={
            readiness.can_serve_validated_forecast
              ? "badge badge-benign"
              : readiness.can_train
              ? "badge badge-info"
              : "badge badge-warning"
          }
        >
          {READINESS_LABEL[readiness.state] || readiness.state}
        </span>
      </div>

      <p style={{ fontSize: "0.82rem", margin: "0.75rem 0", lineHeight: 1.6 }}>
        {readiness.summary}
      </p>

      <div
        style={{
          background: "rgba(255,255,255,0.03)",
          border: "1px solid var(--border-subtle)",
          borderRadius: "6px",
          padding: "0.75rem 0.9rem",
          fontSize: "0.74rem",
          lineHeight: 1.65,
          marginBottom: "1rem",
        }}
      >
        <strong>Prediction target.</strong> {readiness.prediction_target}
        <br />
        <span style={{ color: "var(--text-dim)" }}>
          Observation window {readiness.observation_window_seconds}s · lead time{" "}
          {readiness.lead_time_seconds}s · horizon {readiness.prediction_horizon_seconds}s
        </span>
      </div>

      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(135px, 1fr))",
          gap: "0.9rem",
          marginBottom: "1rem",
        }}
      >
        {[
          ["Stored events", readiness.total_events],
          ["Labelled", readiness.labelled_events],
          ["Incident examples", readiness.positive_events],
          ["Benign examples", readiness.negative_events],
          ["Span (min)", Math.round(readiness.time_span_seconds / 60)],
        ].map(([label, value]) => (
          <div key={label as string}>
            <div style={{ fontSize: "1.3rem", fontWeight: 600 }}>{value as number}</div>
            <div style={{ fontSize: "0.68rem", color: "var(--text-dim)" }}>{label as string}</div>
          </div>
        ))}
      </div>

      <div className="table-container">
        <table style={{ width: "100%", fontSize: "0.74rem" }}>
          <thead>
            <tr>
              <th style={{ textAlign: "left" }}>Requirement</th>
              <th style={{ textAlign: "left" }}>Required</th>
              <th style={{ textAlign: "left" }}>Observed</th>
              <th style={{ textAlign: "center" }}>Met</th>
            </tr>
          </thead>
          <tbody>
            {readiness.requirements.map((r) => (
              <tr key={r.name}>
                <td title={r.detail}>{r.name.replace(/_/g, " ")}</td>
                <td style={{ color: "var(--text-dim)" }}>{r.required}</td>
                <td>{r.observed}</td>
                <td style={{ textAlign: "center" }}>
                  {r.satisfied ? (
                    <span style={{ color: "#10b981" }}>yes</span>
                  ) : (
                    <span style={{ color: "#f43f5e" }}>no</span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {Array.isArray(readiness.label_caveats) && readiness.label_caveats.length > 0 && (
        <div
          style={{
            marginTop: "1rem",
            padding: "0.75rem 0.9rem",
            borderLeft: "3px solid #f59e0b",
            background: "rgba(245, 158, 11, 0.07)",
          }}
        >
          <div style={{ fontSize: "0.75rem", color: "#f59e0b", marginBottom: "0.35rem" }}>
            These labels are not ground truth
          </div>
          <ul style={{ margin: 0, paddingLeft: "1.1rem", fontSize: "0.75rem", lineHeight: 1.7 }}>
            {readiness.label_caveats.map((c, i) => (
              <li key={i}>{c}</li>
            ))}
          </ul>
        </div>
      )}

      {readiness.next_steps.length > 0 && (
        <div style={{ marginTop: "1rem" }}>
          <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginBottom: "0.35rem" }}>
            To become research-ready
          </div>
          <ul style={{ margin: 0, paddingLeft: "1.1rem", fontSize: "0.75rem", lineHeight: 1.7 }}>
            {readiness.next_steps.map((n, i) => (
              <li key={i}>{n}</li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );

  const blockedPanel = blocked && (
    <div
      className="glass-panel"
      style={{ padding: "1.5rem", marginBottom: "1.5rem", borderLeft: "3px solid #f59e0b" }}
    >
      <h3 style={{ margin: "0 0 0.5rem", fontSize: "0.95rem" }}>
        Operation refused: {String(blocked.error).replace(/_/g, " ")}
      </h3>
      <p style={{ fontSize: "0.8rem", lineHeight: 1.6 }}>{blocked.message}</p>

      {Array.isArray(blocked.unmet_requirements) && blocked.unmet_requirements.length > 0 && (
        <ul style={{ fontSize: "0.75rem", paddingLeft: "1.1rem", lineHeight: 1.7 }}>
          {blocked.unmet_requirements.map((u: any, i: number) => (
            <li key={i}>
              <strong>{String(u.name).replace(/_/g, " ")}</strong>: requires {u.required}, observed{" "}
              {u.observed}
            </li>
          ))}
        </ul>
      )}

      {blocked.split_report && (
        <div style={{ fontSize: "0.75rem", color: "var(--text-dim)", lineHeight: 1.7 }}>
          Windows: {blocked.split_report.total_instances} total ·{" "}
          {blocked.split_report.train_instances} training ·{" "}
          {blocked.split_report.purged_instances} purged ·{" "}
          {blocked.split_report.test_instances} holdout (
          {blocked.split_report.test_positive} incident windows)
        </div>
      )}

      {blocked.remediation && (
        <p style={{ fontSize: "0.75rem", color: "var(--text-dim)" }}>{blocked.remediation}</p>
      )}
      {Array.isArray(blocked.next_steps) && (
        <ul style={{ fontSize: "0.75rem", paddingLeft: "1.1rem", lineHeight: 1.7 }}>
          {blocked.next_steps.map((n: string, i: number) => (
            <li key={i}>{n}</li>
          ))}
        </ul>
      )}
    </div>
  );

  const integrityPanel = integrity && (
    <div className="glass-panel" style={{ padding: "1.5rem", marginBottom: "1.5rem" }}>
      <h3 style={{ margin: "0 0 0.25rem", fontSize: "1rem", fontWeight: 600 }}>
        Evaluation Split Integrity
      </h3>
      <p style={{ color: "var(--text-dim)", fontSize: "0.73rem", marginBottom: "0.9rem" }}>
        Training ends before evaluation begins, and the contaminated boundary
        windows between them are purged. Read every metric alongside this.
      </p>
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(130px, 1fr))",
          gap: "0.9rem",
          fontSize: "0.78rem",
        }}
      >
        <div>
          <div style={{ fontSize: "1.2rem", fontWeight: 600 }}>{integrity.train_instances}</div>
          <div style={{ color: "var(--text-dim)", fontSize: "0.68rem" }}>
            training windows ({integrity.train_positive} incident)
          </div>
        </div>
        <div>
          <div style={{ fontSize: "1.2rem", fontWeight: 600, color: "#f59e0b" }}>
            {integrity.purged_instances}
          </div>
          <div style={{ color: "var(--text-dim)", fontSize: "0.68rem" }}>
            purged ({integrity.embargo_seconds}s)
          </div>
        </div>
        <div>
          <div style={{ fontSize: "1.2rem", fontWeight: 600 }}>{integrity.test_instances}</div>
          <div style={{ color: "var(--text-dim)", fontSize: "0.68rem" }}>
            holdout windows ({integrity.test_positive} incident)
          </div>
        </div>
        <div>
          <div style={{ fontSize: "0.78rem" }}>{integrity.split_strategy.replace(/_/g, " ")}</div>
          <div style={{ color: "var(--text-dim)", fontSize: "0.68rem" }}>split strategy</div>
        </div>
      </div>
      {integrity.test_positive === 0 && (
        <div className="badge badge-warning" style={{ marginTop: "0.9rem", display: "block", padding: "0.6rem" }}>
          The holdout contains no incident windows, so detection metrics computed
          on it are undefined and do not demonstrate predictive ability.
        </div>
      )}
    </div>
  );

  return (
    <div className="page-container">
      {readinessPanel}
      {blockedPanel}
      {integrityPanel}
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
              Strict chronological past-train / future-test split, with the contaminated boundary purged. Two baselines, logistic regression, random forest, a window-sequence model and an LSTM — all on the same target, dataset and split.
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
            <p>
              No model has been trained on the current telemetry, so no
              forecast is available.
            </p>
            {readiness && !readiness.can_train ? (
              <p style={{ fontSize: "0.8rem", maxWidth: "34rem", margin: "0.5rem auto 0", lineHeight: 1.6 }}>
                Training is blocked by the research gate: {readiness.summary} See
                Research Readiness above for the unmet requirements.
              </p>
            ) : (
              <button
                className="btn btn-primary"
                onClick={handleTrainModels}
                style={{ marginTop: "1rem" }}
                disabled={training}
              >
                Run Initial Training
              </button>
            )}
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
                  // Derived from the measured PR-AUC, never hardcoded. This
                  // previously named random_forest_forecaster the best model
                  // whatever the numbers said — and with the temporal and
                  // LSTM models added it is frequently not. Baselines are
                  // excluded: a baseline winning is a finding to read, not a
                  // model to recommend.
                  const isBest = k === best;
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
                          {/* A degenerate model has computable metrics and made
                              no distinctions. Saying so beside the figures stops
                              class-balance arithmetic reading as performance. */}
                          {m.predictions_degenerate && (
                            <span
                              className="badge"
                              title={
                                m.scores_constant
                                  ? "The model produced one score for every held-out window, so it ranked nothing."
                                  : "The model predicted a single class for every held-out window."
                              }
                              style={{ fontSize: "0.65rem", background: "rgba(244, 63, 94, 0.2)", color: "#f43f5e" }}
                            >
                              Degenerate
                            </span>
                          )}
                          {!m.predictions_degenerate &&
                            m.discrimination_demonstrated === false && (
                              <span
                                className="badge"
                                title={`PR-AUC does not exceed the no-skill base rate${
                                  m.no_skill_pr_auc != null ? ` (${m.no_skill_pr_auc})` : ""
                                }.`}
                                style={{ fontSize: "0.65rem", background: "rgba(245, 158, 11, 0.2)", color: "#f59e0b" }}
                              >
                                No skill
                              </span>
                            )}
                          {m.discrimination_demonstrated == null && m.sample_adequate === false && (
                            <span
                              className="badge"
                              title="Too few held-out instances, or only one class, to establish anything."
                              style={{ fontSize: "0.65rem", background: "rgba(148, 163, 184, 0.2)", color: "var(--text-dim)" }}
                            >
                              Inconclusive
                            </span>
                          )}
                        </div>
                      </td>
                      <td style={{ fontSize: "0.8rem", color: "var(--text-dim)" }}>{m.model_type}</td>
                      <td>{fmtPercent(m.precision)}</td>
                      <td>{fmtPercent(m.recall)}</td>
                      <td style={{ fontWeight: 600, color: "var(--accent-cyan)" }}>{fmtPercent(m.f1_score ?? m.f1)}</td>
                      <td>{fmtFixed(m.pr_auc, 3, "—")}</td>
                      <td>{fmtFixed(m.roc_auc, 3, "—")}</td>
                      <td>{fmtFixed(m.brier_score, 3, "—")}</td>
                      <td style={{ color: m.false_positive_rate > 0.2 ? "#f43f5e" : "#10b981" }}>
                        {fmtPercent(m.false_positive_rate)}
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
                  {fmtPercent(prediction.propensity_score)}
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
                const maxVal = Math.max(...safeSeries(prediction.top_contributing_features.map((f) => f.impact)), 0.01);
                const pct = isNum(feat.impact)
                  ? Math.min(100, Math.max(10, (feat.impact / maxVal) * 100))
                  : 0;
                return (
                  <div key={idx}>
                    <div style={{ display: "flex", justifyContent: "space-between", fontSize: "0.8rem", marginBottom: "0.25rem" }}>
                      <span style={{ fontWeight: 600, color: "var(--text-main)" }}>{feat.feature}</span>
                      <span style={{ color: "var(--text-dim)" }}>
                        val: <code style={{ color: "var(--accent-cyan)" }}>{fmtFixed(feat.value, 1)}</code> • impact: {fmtFixed(feat.impact, 3)}
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

import { ModelMetrics } from "../types";

/**
 * The best model, derived from the measured PR-AUC.
 *
 * The dashboard previously hardcoded `random_forest_forecaster` as "best"
 * regardless of what the evaluation returned. With a temporal model and an
 * LSTM now competing on the same split, that label was frequently wrong —
 * and a wrong "best" badge is worse than none, because it is read as a
 * result rather than as decoration.
 *
 * Baselines are excluded on purpose. A baseline beating every real model
 * is an important finding about the data, but it is not a model to point
 * an operator at.
 */
export function bestModelId(
  models: Record<string, ModelMetrics> | null | undefined,
): string | null {
  if (!models) return null;

  let best: string | null = null;
  let bestScore = -Infinity;

  for (const [id, metrics] of Object.entries(models)) {
    if (id.startsWith("baseline_")) continue;
    // A model that predicted one class for every window, or ranked nothing,
    // has a computable PR-AUC and no demonstrated skill. Crowning it "best"
    // would present chance-level arithmetic as a result.
    if (metrics?.predictions_degenerate) continue;
    if (metrics?.discrimination_demonstrated === false) continue;
    const score = metrics?.pr_auc;
    if (typeof score !== "number" || !Number.isFinite(score)) continue;
    if (score > bestScore) {
      bestScore = score;
      best = id;
    }
  }
  return best;
}

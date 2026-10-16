import { describe, expect, it } from "vitest";
import { bestModelId } from "../utils/models";
import { ModelMetrics } from "../types";

/**
 * Regression for a fabricated claim in the UI.
 *
 * The model table hardcoded `random_forest_forecaster` as "best"
 * regardless of the evaluated metrics. With a temporal model and an LSTM
 * now competing on the same split, that badge was frequently attached to
 * a model the evaluation had not chosen — and an operator reads a "best"
 * badge as a result, not as decoration.
 */

const m = (
  pr_auc: number | null | undefined,
  extra: Partial<ModelMetrics> = {},
): ModelMetrics => ({ pr_auc, ...extra } as unknown as ModelMetrics);

describe("best model selection", () => {
  it("picks the highest measured PR-AUC, not a hardcoded name", () => {
    const best = bestModelId({
      random_forest_forecaster: m(0.81),
      temporal_window_stack: m(0.93),
      lstm_forecaster: m(0.75),
    });
    expect(best).toBe("temporal_window_stack");
    expect(best).not.toBe("random_forest_forecaster");
  });

  it("excludes baselines even when a baseline scores highest", () => {
    // A baseline winning is a finding about the data, not a recommendation.
    const best = bestModelId({
      baseline_constant: m(0.99),
      baseline_threshold: m(0.97),
      logistic_regression: m(0.42),
    });
    expect(best).toBe("logistic_regression");
  });

  it("ignores models whose PR-AUC is undefined or not finite", () => {
    const best = bestModelId({
      logistic_regression: m(undefined),
      random_forest_forecaster: m(NaN),
      temporal_window_stack: m(0.6),
    });
    expect(best).toBe("temporal_window_stack");
  });

  it("returns null rather than guessing when nothing is scored", () => {
    expect(bestModelId({})).toBeNull();
    expect(bestModelId(null)).toBeNull();
    expect(bestModelId(undefined)).toBeNull();
    expect(bestModelId({ baseline_constant: m(0.9) })).toBeNull();
    expect(bestModelId({ logistic_regression: m(undefined) })).toBeNull();
  });

  it("treats a genuine zero as a score, not as missing", () => {
    expect(bestModelId({ logistic_regression: m(0) })).toBe("logistic_regression");
  });

  it("never crowns a model that predicted a single class", () => {
    // The rehearsal case: a constant predictor scores PR-AUC equal to the
    // base rate. The number is computable; the model made no distinction.
    const best = bestModelId({
      lstm_forecaster: m(0.95, { predictions_degenerate: true }),
      random_forest_forecaster: m(0.61),
    });
    expect(best).toBe("random_forest_forecaster");
  });

  it("never crowns a model that failed to beat the no-skill line", () => {
    const best = bestModelId({
      temporal_window_stack: m(0.9, { discrimination_demonstrated: false }),
      logistic_regression: m(0.55, { discrimination_demonstrated: true }),
    });
    expect(best).toBe("logistic_regression");
  });

  it("returns null when every candidate is degenerate", () => {
    expect(
      bestModelId({
        a_model: m(0.99, { predictions_degenerate: true }),
        b_model: m(0.98, { discrimination_demonstrated: false }),
      }),
    ).toBeNull();
  });

  it("still ranks models whose discrimination is undetermined", () => {
    // null means "the sample could not establish it", which is not the same
    // as "it failed". Such a model is still shown, flagged elsewhere.
    const best = bestModelId({
      a_model: m(0.7, { discrimination_demonstrated: null }),
      b_model: m(0.4, { discrimination_demonstrated: null }),
    });
    expect(best).toBe("a_model");
  });

  it("is stable when two models tie", () => {
    const models = { a_model: m(0.8), b_model: m(0.8) };
    expect(bestModelId(models)).toBe(bestModelId(models));
  });
});

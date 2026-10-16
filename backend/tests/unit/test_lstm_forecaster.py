"""
LSTM correctness tests.

This is a hand-written backpropagation-through-time implementation, so
"it trains and the loss goes down" is not evidence that it is right — a
subtly wrong gradient produces a perfectly plausible loss curve. Two
things are therefore checked directly:

  * every parameter's analytic gradient against a central finite
    difference, and
  * that the recurrence genuinely carries information, by learning a task
    whose answer is visible only in the first timestep.

Nothing here says the model is useful on security telemetry. It says the
implementation is a working LSTM.
"""

from __future__ import annotations

import numpy as np
import pytest

from app.models.lstm_forecaster import (
    LSTMForecaster,
    gradient_check,
    to_sequences,
)


# ──────────────────────────────────────────────────────────────────
# Gradient correctness
# ──────────────────────────────────────────────────────────────────


def test_analytic_gradients_match_finite_differences():
    rng = np.random.default_rng(0)
    X = rng.normal(size=(12, 5, 4))
    y = (rng.random(12) < 0.4).astype(float)

    worst = gradient_check(LSTMForecaster(hidden_size=6, seed=1), X, y, n_samples=30)

    assert worst < 1e-5, (
        f"max relative gradient error {worst:.2e}; backpropagation through "
        "time is wrong somewhere"
    )


def test_gradient_check_holds_for_a_longer_sequence():
    """Errors in the recurrent term compound with depth, so check a longer one."""
    rng = np.random.default_rng(5)
    X = rng.normal(size=(8, 12, 3))
    y = (rng.random(8) < 0.5).astype(float)

    worst = gradient_check(LSTMForecaster(hidden_size=5, seed=2), X, y, n_samples=25)
    assert worst < 1e-5


def test_gradient_check_for_a_single_timestep():
    rng = np.random.default_rng(9)
    X = rng.normal(size=(10, 1, 4))
    y = (rng.random(10) < 0.5).astype(float)
    assert gradient_check(LSTMForecaster(hidden_size=4, seed=3), X, y) < 1e-5


# ──────────────────────────────────────────────────────────────────
# Memory — is it actually recurrent?
# ──────────────────────────────────────────────────────────────────


def _first_step_memory_task(n=240, timesteps=8, features=3, seed=3):
    """
    The label is decided entirely by timestep 0; every later step is noise.
    A model without memory cannot beat chance.
    """
    rng = np.random.default_rng(seed)
    y = (rng.random(n) < 0.5).astype(float)
    X = rng.normal(0, 1.0, size=(n, timesteps, features))
    X[:, 0, 0] = np.where(y == 1, 3.0, -3.0)
    X[:, 1:, 0] = rng.normal(0, 1.0, size=(n, timesteps - 1))
    return X, y


def test_model_carries_information_across_timesteps():
    X, y = _first_step_memory_task()
    model = LSTMForecaster(hidden_size=12, epochs=250, learning_rate=0.03, seed=7)
    model.fit(X[:180], y[:180])

    accuracy = float(np.mean(model.predict(X[180:]) == y[180:]))
    assert accuracy > 0.85, (
        f"holdout accuracy {accuracy:.3f} on a task solvable only with "
        "memory; the recurrence is not carrying information"
    )


def test_a_last_step_only_model_would_fail_the_same_task():
    """
    Confirms the task really does require memory, rather than the LSTM
    having found an easier route to the answer.
    """
    from sklearn.linear_model import LogisticRegression

    X, y = _first_step_memory_task()
    last_step = X[:, -1, :]  # no history at all
    clf = LogisticRegression(max_iter=500).fit(last_step[:180], y[:180])
    accuracy = float(np.mean(clf.predict(last_step[180:]) == y[180:]))

    assert accuracy < 0.70, (
        f"a memoryless model scored {accuracy:.3f}; the task does not "
        "actually require memory and the test above proves nothing"
    )


def test_training_reduces_the_loss():
    X, y = _first_step_memory_task(n=120, seed=11)
    model = LSTMForecaster(hidden_size=8, epochs=120, seed=4).fit(X, y)
    assert model.loss_history[-1] < model.loss_history[0] * 0.5


# ──────────────────────────────────────────────────────────────────
# Interface and numerical robustness
# ──────────────────────────────────────────────────────────────────


def test_predict_proba_matches_the_sklearn_convention():
    X, y = _first_step_memory_task(n=60, seed=2)
    model = LSTMForecaster(hidden_size=6, epochs=30, seed=5).fit(X, y)

    probs = model.predict_proba(X)
    assert probs.shape == (60, 2)
    np.testing.assert_allclose(probs.sum(axis=1), 1.0, atol=1e-9)
    assert ((probs >= 0.0) & (probs <= 1.0)).all()


def test_results_are_deterministic_for_a_given_seed():
    X, y = _first_step_memory_task(n=80, seed=6)
    a = LSTMForecaster(hidden_size=6, epochs=40, seed=13).fit(X, y).predict_proba(X)
    b = LSTMForecaster(hidden_size=6, epochs=40, seed=13).fit(X, y).predict_proba(X)
    np.testing.assert_allclose(a, b)


def test_standardisation_is_fitted_on_training_data_only():
    """
    Fitting the scaler on everything would leak test statistics into
    training — the same contamination the chronological purge prevents.
    """
    rng = np.random.default_rng(8)
    train = rng.normal(0, 1, size=(40, 4, 3))
    y = (rng.random(40) < 0.5).astype(float)
    model = LSTMForecaster(hidden_size=4, epochs=10, seed=1).fit(train, y)

    train_mean = model._mean.copy()
    # Scoring wildly different data must not move the fitted statistics.
    model.predict_proba(rng.normal(500, 50, size=(10, 4, 3)))
    np.testing.assert_allclose(model._mean, train_mean)


def test_a_constant_feature_does_not_produce_nan():
    """Zero spread would divide by zero in standardisation."""
    X = np.zeros((30, 4, 3))
    X[:, :, 0] = 7.0  # constant
    rng = np.random.default_rng(1)
    X[:, :, 1:] = rng.normal(size=(30, 4, 2))
    y = (rng.random(30) < 0.5).astype(float)

    probs = LSTMForecaster(hidden_size=4, epochs=20, seed=1).fit(X, y).predict_proba(X)
    assert np.isfinite(probs).all()


def test_extreme_inputs_do_not_overflow_the_sigmoid():
    X = np.full((10, 3, 2), 1e6)
    X[5:] = -1e6
    y = np.array([1.0] * 5 + [0.0] * 5)
    probs = LSTMForecaster(hidden_size=4, epochs=10, seed=1).fit(X, y).predict_proba(X)
    assert np.isfinite(probs).all()


def test_unfitted_model_refuses_to_predict():
    with pytest.raises(RuntimeError):
        LSTMForecaster().predict_proba(np.zeros((2, 3, 2)))


def test_wrong_input_rank_is_rejected():
    model = LSTMForecaster()
    with pytest.raises(ValueError):
        model.fit(np.zeros((10, 4)), np.zeros(10))


def test_mismatched_lengths_are_rejected():
    with pytest.raises(ValueError):
        LSTMForecaster().fit(np.zeros((10, 3, 2)), np.zeros(9))


# ──────────────────────────────────────────────────────────────────
# Sequence shaping
# ──────────────────────────────────────────────────────────────────


def test_to_sequences_preserves_chronological_order():
    X = np.arange(20, dtype=float).reshape(10, 2)
    y = np.arange(10)

    seqs, labels = to_sequences(X, y, timesteps=3)

    assert seqs.shape == (8, 3, 2)
    np.testing.assert_array_equal(seqs[0], X[0:3])
    np.testing.assert_array_equal(seqs[-1], X[7:10])
    np.testing.assert_array_equal(labels, y[2:])


def test_to_sequences_returns_nothing_without_enough_history():
    X = np.ones((2, 3))
    seqs, labels = to_sequences(X, np.zeros(2), timesteps=5)
    assert len(seqs) == 0 and len(labels) == 0


def test_to_sequences_rejects_a_nonsensical_window():
    with pytest.raises(ValueError):
        to_sequences(np.ones((5, 2)), np.zeros(5), timesteps=0)

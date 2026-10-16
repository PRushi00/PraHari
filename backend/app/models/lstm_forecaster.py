"""
PraHari — Minimal LSTM Sequence Forecaster

The blueprint names an LSTM as the intended temporal architecture. This is
one: a single-layer LSTM with a sigmoid read-out, trained by
backpropagation through time with Adam, implemented in NumPy.

Why from scratch
----------------
A recurrent model normally means adding PyTorch or TensorFlow. Installing
either is outside this project's agreed boundary, and both are large
downloads for a model that, on the data available here, operates on a few
hundred sequences of a dozen timesteps. NumPy is already a dependency and
is entirely adequate at that size.

The cost is that correctness has to be demonstrated rather than assumed,
so two things are tested directly:

  * **Gradient correctness** — every parameter's analytic gradient is
    checked against a central finite difference.
  * **Memory** — the model is trained on a task whose label depends only
    on the *first* timestep, which a bag-of-features model cannot solve
    above chance. Passing that shows the recurrence actually carries
    information forward.

What this is not
----------------
It is not fast, not distributed, and not a replacement for a mature
framework. It has one layer, no dropout, no attention, no early stopping
beyond a fixed epoch budget.

**And it is not evidence that PraHari forecasts threats.** It is evaluated
on the same target, dataset and purged chronological split as every other
model. On synthetic data that comparison says which model best recovers
the generator's rule — nothing more.
"""

from __future__ import annotations

import logging
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)

DEFAULT_HIDDEN = 16
DEFAULT_EPOCHS = 150
DEFAULT_LR = 0.02
DEFAULT_SEED = 42
GRAD_CLIP = 5.0


def _sigmoid(z: np.ndarray) -> np.ndarray:
    # Branch to avoid overflow in exp for large-magnitude inputs.
    out = np.empty_like(z)
    pos = z >= 0
    out[pos] = 1.0 / (1.0 + np.exp(-z[pos]))
    ez = np.exp(z[~pos])
    out[~pos] = ez / (1.0 + ez)
    return out


class LSTMForecaster:
    """
    Single-layer LSTM over a window sequence, read out at the last step.

    Input is ``(n_samples, timesteps, n_features)``. Feature standardisation
    is fitted on the training tensor only and reused at predict time —
    fitting it on the full dataset would leak test statistics into
    training, which is the same contamination the chronological purge
    exists to prevent.
    """

    def __init__(
        self,
        hidden_size: int = DEFAULT_HIDDEN,
        epochs: int = DEFAULT_EPOCHS,
        learning_rate: float = DEFAULT_LR,
        seed: int = DEFAULT_SEED,
        verbose: bool = False,
    ):
        self.hidden_size = int(hidden_size)
        self.epochs = int(epochs)
        self.learning_rate = float(learning_rate)
        self.seed = int(seed)
        self.verbose = verbose

        self.W: Optional[np.ndarray] = None   # (4H, F + H)
        self.b: Optional[np.ndarray] = None   # (4H,)
        self.w_out: Optional[np.ndarray] = None  # (H,)
        self.b_out: float = 0.0

        self._mean: Optional[np.ndarray] = None
        self._scale: Optional[np.ndarray] = None
        self._pos_weight: float = 1.0
        self.loss_history: list[float] = []

    # ── parameter handling ────────────────────────────────────────

    def _init_params(self, n_features: int) -> None:
        rng = np.random.default_rng(self.seed)
        H = self.hidden_size
        # Xavier-ish scaling keeps the initial gate pre-activations in the
        # responsive part of the sigmoid.
        limit = np.sqrt(1.0 / (n_features + H))
        self.W = rng.uniform(-limit, limit, size=(4 * H, n_features + H))
        self.b = np.zeros(4 * H)
        # Forget-gate bias at 1: without it an untrained LSTM forgets almost
        # everything on the first step and the memory test below fails for
        # reasons that have nothing to do with the data.
        self.b[H : 2 * H] = 1.0
        self.w_out = rng.uniform(-limit, limit, size=H)
        self.b_out = 0.0

    def get_params_flat(self) -> np.ndarray:
        return np.concatenate(
            [self.W.ravel(), self.b.ravel(), self.w_out.ravel(), [self.b_out]]
        )

    def set_params_flat(self, flat: np.ndarray) -> None:
        H, F = self.hidden_size, self.W.shape[1] - self.hidden_size
        i = 0
        n = 4 * H * (F + H)
        self.W = flat[i : i + n].reshape(4 * H, F + H); i += n
        self.b = flat[i : i + 4 * H].copy(); i += 4 * H
        self.w_out = flat[i : i + H].copy(); i += H
        self.b_out = float(flat[i])

    # ── standardisation ───────────────────────────────────────────

    def _fit_scaler(self, X: np.ndarray) -> None:
        flat = X.reshape(-1, X.shape[2])
        self._mean = flat.mean(axis=0)
        scale = flat.std(axis=0)
        # A constant feature has zero spread; dividing by it produces inf.
        scale[scale < 1e-8] = 1.0
        self._scale = scale

    def _standardise(self, X: np.ndarray) -> np.ndarray:
        if self._mean is None:
            return X
        return (X - self._mean) / self._scale

    # ── forward / backward ────────────────────────────────────────

    def _forward(self, X: np.ndarray):
        """Run the sequence. Returns logits and the cache needed for BPTT."""
        N, T, F = X.shape
        H = self.hidden_size
        h = np.zeros((N, H))
        c = np.zeros((N, H))
        cache = []

        for t in range(T):
            xt = X[:, t, :]
            concat = np.concatenate([xt, h], axis=1)        # (N, F+H)
            z = concat @ self.W.T + self.b                   # (N, 4H)
            i_g = _sigmoid(z[:, :H])
            f_g = _sigmoid(z[:, H : 2 * H])
            o_g = _sigmoid(z[:, 2 * H : 3 * H])
            g_g = np.tanh(z[:, 3 * H :])

            c_prev = c
            c = f_g * c_prev + i_g * g_g
            tanh_c = np.tanh(c)
            h = o_g * tanh_c

            cache.append((concat, i_g, f_g, o_g, g_g, c_prev, c, tanh_c, h))

        logits = h @ self.w_out + self.b_out
        return logits, cache

    def _loss_and_grads(self, X: np.ndarray, y: np.ndarray):
        """
        Binary cross-entropy with positive-class weighting, and its exact
        gradients by backpropagation through time.

        Incidents are the minority class by construction. Without the
        weight the model can reach a low loss by predicting "quiet" always,
        which is precisely the degenerate behaviour the constant baseline
        already represents.
        """
        N, T, _ = X.shape
        H = self.hidden_size
        logits, cache = self._forward(X)
        p = _sigmoid(logits)
        eps = 1e-12

        w = np.where(y == 1, self._pos_weight, 1.0)
        loss = -np.sum(w * (y * np.log(p + eps) + (1 - y) * np.log(1 - p + eps))) / N

        # d(loss)/d(logits) for weighted BCE
        dlogits = w * (p - y) / N                            # (N,)

        dW = np.zeros_like(self.W)
        db = np.zeros_like(self.b)
        dw_out = cache[-1][8].T @ dlogits                    # (H,)
        db_out = float(dlogits.sum())

        dh = np.outer(dlogits, self.w_out)                   # (N, H)
        dc = np.zeros((N, H))

        for t in reversed(range(T)):
            concat, i_g, f_g, o_g, g_g, c_prev, c_t, tanh_c, _ = cache[t]

            do = dh * tanh_c
            dc = dc + dh * o_g * (1.0 - tanh_c ** 2)

            di = dc * g_g
            dg = dc * i_g
            df = dc * c_prev
            dc_prev = dc * f_g

            dz_i = di * i_g * (1.0 - i_g)
            dz_f = df * f_g * (1.0 - f_g)
            dz_o = do * o_g * (1.0 - o_g)
            dz_g = dg * (1.0 - g_g ** 2)
            dz = np.concatenate([dz_i, dz_f, dz_o, dz_g], axis=1)   # (N, 4H)

            dW += dz.T @ concat
            db += dz.sum(axis=0)

            dconcat = dz @ self.W                             # (N, F+H)
            dh = dconcat[:, -H:]
            dc = dc_prev

        return loss, dW, db, dw_out, db_out

    # ── training ──────────────────────────────────────────────────

    def fit(self, X: np.ndarray, y: np.ndarray) -> "LSTMForecaster":
        X = np.asarray(X, dtype=float)
        y = np.asarray(y, dtype=float).ravel()
        if X.ndim != 3:
            raise ValueError(f"expected (n, timesteps, features), got {X.shape}")
        if len(X) != len(y):
            raise ValueError("X and y lengths differ")

        self._fit_scaler(X)
        Xs = self._standardise(X)
        self._init_params(X.shape[2])

        positives = float(y.sum())
        negatives = float(len(y) - positives)
        self._pos_weight = (negatives / positives) if positives > 0 else 1.0

        # Adam
        m_W = np.zeros_like(self.W); v_W = np.zeros_like(self.W)
        m_b = np.zeros_like(self.b); v_b = np.zeros_like(self.b)
        m_o = np.zeros_like(self.w_out); v_o = np.zeros_like(self.w_out)
        m_bo = 0.0; v_bo = 0.0
        beta1, beta2, eps = 0.9, 0.999, 1e-8

        self.loss_history = []
        for step in range(1, self.epochs + 1):
            loss, dW, db, dw_out, db_out = self._loss_and_grads(Xs, y)
            self.loss_history.append(float(loss))

            # Exploding gradients are the classic BPTT failure; clip by norm.
            total_norm = np.sqrt(
                (dW ** 2).sum() + (db ** 2).sum() + (dw_out ** 2).sum() + db_out ** 2
            )
            if total_norm > GRAD_CLIP:
                scale = GRAD_CLIP / (total_norm + 1e-12)
                dW *= scale; db *= scale; dw_out *= scale; db_out *= scale

            m_W = beta1 * m_W + (1 - beta1) * dW
            v_W = beta2 * v_W + (1 - beta2) * dW ** 2
            m_b = beta1 * m_b + (1 - beta1) * db
            v_b = beta2 * v_b + (1 - beta2) * db ** 2
            m_o = beta1 * m_o + (1 - beta1) * dw_out
            v_o = beta2 * v_o + (1 - beta2) * dw_out ** 2
            m_bo = beta1 * m_bo + (1 - beta1) * db_out
            v_bo = beta2 * v_bo + (1 - beta2) * db_out ** 2

            bc1 = 1 - beta1 ** step
            bc2 = 1 - beta2 ** step
            lr = self.learning_rate

            self.W -= lr * (m_W / bc1) / (np.sqrt(v_W / bc2) + eps)
            self.b -= lr * (m_b / bc1) / (np.sqrt(v_b / bc2) + eps)
            self.w_out -= lr * (m_o / bc1) / (np.sqrt(v_o / bc2) + eps)
            self.b_out -= lr * (m_bo / bc1) / (np.sqrt(v_bo / bc2) + eps)

            if self.verbose and step % 25 == 0:
                logger.info("LSTM epoch %d/%d loss=%.5f", step, self.epochs, loss)

        return self

    # ── inference ─────────────────────────────────────────────────

    def predict_proba(self, X: np.ndarray) -> np.ndarray:
        """Two-column probabilities, matching the scikit-learn convention."""
        X = np.asarray(X, dtype=float)
        if self.W is None:
            raise RuntimeError("model is not fitted")
        logits, _ = self._forward(self._standardise(X))
        p = _sigmoid(logits)
        return np.column_stack([1.0 - p, p])

    def predict(self, X: np.ndarray) -> np.ndarray:
        return (self.predict_proba(X)[:, 1] >= 0.5).astype(int)


# ──────────────────────────────────────────────────────────────────
# Shaping and verification helpers
# ──────────────────────────────────────────────────────────────────


def to_sequences(
    X: np.ndarray, y: np.ndarray, timesteps: int
) -> tuple[np.ndarray, np.ndarray]:
    """
    Turn a chronological matrix of windows into overlapping sequences.

    Instance *i* becomes windows ``i-timesteps+1 … i``. As with the stacked
    temporal model, this must be applied **after** the train/test split and
    separately to each side: applied before, a test sequence near the
    boundary would reach back into the training period and reintroduce
    exactly the contamination the purge removes.
    """
    if timesteps < 1:
        raise ValueError("timesteps must be at least 1")
    if len(X) < timesteps:
        return np.empty((0, timesteps, X.shape[1])), np.empty((0,))
    seqs = np.stack(
        [X[i - timesteps + 1 : i + 1] for i in range(timesteps - 1, len(X))]
    )
    return seqs, y[timesteps - 1 :]


def gradient_check(
    model: LSTMForecaster,
    X: np.ndarray,
    y: np.ndarray,
    n_samples: int = 25,
    epsilon: float = 1e-5,
    seed: int = 0,
) -> float:
    """
    Maximum relative error between analytic and numerical gradients.

    A hand-written BPTT pass that is subtly wrong still trains to a
    plausible-looking loss curve, so the gradients are checked directly
    rather than inferred from the model appearing to learn.
    """
    model._fit_scaler(X)
    Xs = model._standardise(X)
    if model.W is None:
        model._init_params(X.shape[2])
    y = np.asarray(y, dtype=float).ravel()
    positives = float(y.sum())
    model._pos_weight = (
        (len(y) - positives) / positives if positives > 0 else 1.0
    )

    _, dW, db, dw_out, db_out = model._loss_and_grads(Xs, y)
    analytic = np.concatenate(
        [dW.ravel(), db.ravel(), dw_out.ravel(), [db_out]]
    )

    theta = model.get_params_flat()
    rng = np.random.default_rng(seed)
    idx = rng.choice(len(theta), size=min(n_samples, len(theta)), replace=False)

    worst = 0.0
    for j in idx:
        original = theta[j]

        theta[j] = original + epsilon
        model.set_params_flat(theta)
        plus, *_ = model._loss_and_grads(Xs, y)

        theta[j] = original - epsilon
        model.set_params_flat(theta)
        minus, *_ = model._loss_and_grads(Xs, y)

        theta[j] = original
        model.set_params_flat(theta)

        numeric = (plus - minus) / (2 * epsilon)
        denom = max(1e-8, abs(numeric) + abs(analytic[j]))
        worst = max(worst, abs(numeric - analytic[j]) / denom)

    return worst

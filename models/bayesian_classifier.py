"""
Bayesian Classifier for IoT Network Intrusion Detection
=======================================================
Implements a mathematically rigorous Mixed (Gaussian + Categorical) Naive Bayes
classifier for network intrusion detection in IoT environments.

Mathematical Formulation:
-------------------------
For a feature vector x = (x_cont, x_cat) and class C_k where k in {0, 1}
(0: Normal, 1: Attack):

1. Prior Probability:
   P(C_k) = (N_k + alpha) / (N + 2 * alpha)

2. Continuous Likelihood (Gaussian PDF):
   P(x_c | C_k) = (1 / sqrt(2 * pi * sigma_{k,c}^2)) * exp(-(x_c - mu_{k,c})^2 / (2 * sigma_{k,c}^2))

3. Categorical Likelihood (Laplace-smoothed frequency):
   P(x_d = v | C_k) = (Count(x_d = v, C_k) + alpha) / (N_k + alpha * |V_d|)

4. Joint Log-Posterior:
   ln P(C_k | x) = ln P(C_k) + sum_c ln P(x_c | C_k) + sum_d ln P(x_d | C_k)

5. Softmax Normalization:
   P(C_1 | x) = exp(z_1 - z_max) / (exp(z_0 - z_max) + exp(z_1 - z_max))
   where z_k = ln P(C_k | x) and z_max = max(z_0, z_1)
"""

import math
import numpy as np
import pandas as pd


class BayesianClassifier:
    """Exact Mixed Naive Bayes Classifier with explainable log-odds evidence."""

    def __init__(self, alpha: float = 1.0, var_smoothing: float = 1e-9):
        self.alpha = alpha
        self.var_smoothing = var_smoothing
        self.is_trained = False
        
        self.classes = [0, 1]
        self.class_counts = {0: 0, 1: 0}
        self.priors = {0: 0.5, 1: 0.5}
        
        self.cont_cols = [
            'network_packet_size',
            'session_duration',
            'ip_reputation_score',
            'login_attempts',
        ]
        self.cat_cols = [
            'protocol_type',
            'encryption_used',
            'browser_type',
            'failed_logins',
            'unusual_time_access',
        ]
        
        # Parameters
        self.gaussian_params = {}  # {class: {col: (mean, var)}}
        self.categorical_params = {}  # {class: {col: {val: prob, '__default__': prob}}}
        self.vocabulary = {}  # {col: set of unique values}
        self.evaluation_metrics = {}

    def fit(self, df: pd.DataFrame, target_col: str = 'attack_detected'):
        """Train the classifier on the provided DataFrame."""
        df_clean = df.copy()
        if 'encryption_used' in df_clean.columns:
            df_clean['encryption_used'] = df_clean['encryption_used'].fillna('None')

        n_total = len(df_clean)
        if n_total == 0:
            raise ValueError("Training dataset cannot be empty")

        for c in self.classes:
            subset = df_clean[df_clean[target_col] == c]
            n_c = len(subset)
            self.class_counts[c] = n_c
            # Laplace-smoothed class prior
            self.priors[c] = (n_c + self.alpha) / (n_total + len(self.classes) * self.alpha)

            # Continuous Gaussian parameters
            self.gaussian_params[c] = {}
            for col in self.cont_cols:
                if col in df_clean.columns:
                    col_vals = pd.to_numeric(subset[col], errors='coerce').fillna(0)
                    mean = float(col_vals.mean())
                    var = float(col_vals.var())
                    if math.isnan(var) or var < self.var_smoothing:
                        var = self.var_smoothing
                    self.gaussian_params[c][col] = (mean, var)

            # Categorical frequency tables
            self.categorical_params[c] = {}
            for col in self.cat_cols:
                if col in df_clean.columns:
                    unique_vals = set(df_clean[col].dropna().unique())
                    self.vocabulary[col] = unique_vals
                    counts = subset[col].value_counts().to_dict()
                    denom = n_c + self.alpha * max(1, len(unique_vals))
                    self.categorical_params[c][col] = {
                        val: (counts.get(val, 0) + self.alpha) / denom
                        for val in unique_vals
                    }
                    self.categorical_params[c][col]['__default__'] = self.alpha / denom

        self.is_trained = True
        return self

    def predict_log_likelihoods(self, sample: dict):
        """Compute log P(C_k | x) and feature evidence decomposition."""
        if not self.is_trained:
            raise RuntimeError("Classifier must be trained before predicting.")

        log_posteriors = {}
        evidence_by_class = {}

        for c in self.classes:
            lp = math.log(self.priors[c])
            feat_ev = {}

            # Continuous features
            for col in self.cont_cols:
                if col in sample and col in self.gaussian_params[c]:
                    val = float(sample.get(col, 0))
                    mean, var = self.gaussian_params[c][col]
                    # ln Gaussian PDF = -0.5 * ln(2*pi*var) - ((x - mu)^2)/(2*var)
                    log_pdf = -0.5 * math.log(2 * math.pi * var) - ((val - mean) ** 2) / (2 * var)
                    lp += log_pdf
                    feat_ev[col] = log_pdf

            # Categorical features
            for col in self.cat_cols:
                if col in sample and col in self.categorical_params[c]:
                    val = sample.get(col)
                    if val is None or (isinstance(val, float) and math.isnan(val)):
                        val = 'None' if col == 'encryption_used' else val
                    prob = self.categorical_params[c][col].get(
                        val, self.categorical_params[c][col]['__default__']
                    )
                    log_prob = math.log(max(prob, 1e-12))
                    lp += log_prob
                    feat_ev[col] = log_prob

            log_posteriors[c] = lp
            evidence_by_class[c] = feat_ev

        return log_posteriors, evidence_by_class

    def predict_sample(self, sample: dict):
        """Predict class, posterior probability, and feature evidence for a single sample."""
        log_posts, evidence = self.predict_log_likelihoods(sample)

        z0 = log_posts[0]
        z1 = log_posts[1]
        z_max = max(z0, z1)

        exp0 = math.exp(z0 - z_max)
        exp1 = math.exp(z1 - z_max)
        sum_exp = exp0 + exp1

        p0 = exp0 / sum_exp
        p1 = exp1 / sum_exp

        # Feature evidence: log-odds ratio = ln P(x_i | Attack) - ln P(x_i | Normal)
        feature_contributions = {}
        for col in self.cont_cols + self.cat_cols:
            if col in evidence[1] and col in evidence[0]:
                feature_contributions[col] = round(evidence[1][col] - evidence[0][col], 4)

        return {
            'predicted_class': 1 if p1 >= 0.5 else 0,
            'probability_attack': float(p1),
            'probability_normal': float(p0),
            'log_odds': float(z1 - z0),
            'feature_contributions': feature_contributions,
        }

    def evaluate(self, test_df: pd.DataFrame, target_col: str = 'attack_detected'):
        """Compute standard evaluation metrics on a test DataFrame."""
        y_true = []
        y_pred = []
        y_prob = []

        for _, row in test_df.iterrows():
            sample = row.to_dict()
            res = self.predict_sample(sample)
            y_prob.append(res['probability_attack'])
            y_pred.append(res['predicted_class'])
            y_true.append(int(row[target_col]))

        y_true = np.array(y_true)
        y_pred = np.array(y_pred)
        y_prob = np.array(y_prob)

        tp = int(np.sum((y_true == 1) & (y_pred == 1)))
        tn = int(np.sum((y_true == 0) & (y_pred == 0)))
        fp = int(np.sum((y_true == 0) & (y_pred == 1)))
        fn = int(np.sum((y_true == 1) & (y_pred == 0)))

        accuracy = float((tp + tn) / len(y_true)) if len(y_true) > 0 else 0.0
        precision = float(tp / (tp + fp)) if (tp + fp) > 0 else 0.0
        recall = float(tp / (tp + fn)) if (tp + fn) > 0 else 0.0
        f1 = float(2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

        # Approximate ROC-AUC via rank-sum (Mann-Whitney U statistic)
        pos_probs = y_prob[y_true == 1]
        neg_probs = y_prob[y_true == 0]
        if len(pos_probs) > 0 and len(neg_probs) > 0:
            # count pairs where pos > neg
            auc_pairs = 0
            for p in pos_probs:
                auc_pairs += np.sum(p > neg_probs) + 0.5 * np.sum(p == neg_probs)
            roc_auc = float(auc_pairs / (len(pos_probs) * len(neg_probs)))
        else:
            roc_auc = 0.5

        self.evaluation_metrics = {
            'total_samples': len(y_true),
            'accuracy': round(accuracy, 4),
            'precision': round(precision, 4),
            'recall': round(recall, 4),
            'f1_score': round(f1, 4),
            'roc_auc': round(roc_auc, 4),
            'confusion_matrix': {
                'tp': tp,
                'tn': tn,
                'fp': fp,
                'fn': fn,
            },
        }
        return self.evaluation_metrics

# =============================================================================
# TOP-FEATURE ANALYSIS - ALL EXPERIMENTS x ALL DATASETS (self-contained cell)
# Experiments: JA4 | JA4+JA4S | JA4+JA4S+JA4T | JA4+JA4S+JA4T+JA4TS | JA4+JA4X | JA4* (all)
# For each (dataset, experiment): clean -> per-device split -> RF on all decomposed
# fields -> importance grouped by original field -> retrain with top-k fields ->
# paired comparison on the same test rows -> figures + Excel.
# Top-k is set per experiment (fixed k ~50% of fields) and validated with a k-sweep that
# reports the minimum k not significantly worse than the full model (McNemar).
# All names are prefixed with TF_/tf_ so no notebook global is overwritten.
# =============================================================================
import os, time, warnings
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, top_k_accuracy_score
from scipy.stats import ttest_rel
from statsmodels.stats.contingency_tables import mcnemar

# ------------------------------- CONFIGURATION -------------------------------
TF_EXPERIMENTS = {                       # experiment name -> JA4+ families used
    "JA4":                 ["ja4"],
    "JA4+JA4S":            ["ja4", "ja4s"],
    "JA4+JA4S+JA4T":       ["ja4", "ja4s", "ja4t"],
    "JA4+JA4S+JA4T+JA4TS": ["ja4", "ja4s", "ja4t", "ja4ts"],
    "JA4+JA4X":            ["ja4", "ja4x"],
    "JA4*":                ["ja4", "ja4s", "ja4t", "ja4ts", "ja4x"],
}
TF_ALL_FEATURES = [
    "ja4_protocol", "ja4_tls_version", "ja4_sni_type", "ja4_n_ciphers", "ja4_n_extensions",
    "ja4_alpn", "ja4_cipher_hash", "ja4_extension_hash",
    "ja4s_protocol", "ja4s_tls_version", "ja4s_n_extensions", "ja4s_alpn",
    "ja4s_cipher_chosen", "ja4s_extension_hash",
    "ja4t_window_size", "ja4t_option_list", "ja4t_mss", "ja4t_scale",
    "ja4t_num_options", "ja4t_has_timestamp", "ja4t_has_sack", "ja4t_has_window_scale",
    "ja4ts_window_size", "ja4ts_option_list", "ja4ts_mss", "ja4ts_scale",
    "ja4ts_num_options", "ja4ts_has_timestamp", "ja4ts_has_sack", "ja4ts_has_window_scale",
    "ja4x_issuer_hash", "ja4x_subject_hash", "ja4x_extensions_hash",
]
TF_NUMERIC = [
    "ja4_n_ciphers", "ja4_n_extensions", "ja4s_n_extensions",
    "ja4t_window_size", "ja4t_mss", "ja4t_scale", "ja4t_num_options",
    "ja4t_has_timestamp", "ja4t_has_sack", "ja4t_has_window_scale",
    "ja4ts_window_size", "ja4ts_mss", "ja4ts_scale", "ja4ts_num_options",
    "ja4ts_has_timestamp", "ja4ts_has_sack", "ja4ts_has_window_scale",
]
TF_CATEGORICAL = [c for c in TF_ALL_FEATURES if c not in TF_NUMERIC]
TF_TARGET = "device_name"

# --- Number of original fields kept (top-k) ---
TF_TOP_K_PER_EXPERIMENT = {   # fixed k per experiment (~50% of its decomposed fields)
    "JA4": 4, "JA4+JA4S": 7, "JA4+JA4X": 6,
    "JA4+JA4S+JA4T": 11, "JA4+JA4S+JA4T+JA4TS": 15, "JA4*": 16,
}                             # experiments not listed here use half of their fields
TF_RUN_K_SWEEP = True         # evaluate several k and find the minimum k not significantly worse than the full model
TF_K_SWEEP = [1, 2, 3, 4, 6, 8, 10, 12, 16, 20, 24]   # candidate k (values >= number of fields are ignored; the fixed k is always added)
TF_PRIMARY_K_MODE = "fixed"   # "fixed": main comparison uses the k above | "auto": uses the k found by the sweep
TF_ALPHA = 0.05               # McNemar significance level used by the sweep
TF_SPLIT_SEED = 42
TF_TEST_SIZE = 0.2
TF_N_BOOTSTRAPS = 1000
TF_RF_PARAMS = dict(n_estimators=100, max_depth=20, class_weight="balanced", random_state=42, n_jobs=-1)
TF_SHOW_FIGURES = True        # False: figures are still saved to disk, but not displayed
TF_INVALID_TOKENS = {"", "nan", "none", "(empty)", "(emtpy)"}

# Reuse the notebook's dataset/output configuration when it exists (Section 0); otherwise use these defaults.
_BASE = r"C:\Users\gemma\Desktop\TFG_GemmaBeatrizVate\UNSW-IoTraffic"
TF_DATASETS = globals().get("DATASETS_CONFIG") or {
    "UNSW":    {"path": rf"{_BASE}\1_Data\raw_fingerprints\unsw_raw_features.csv",    "min_samples": 5, "max_samples": 500},
    "CIC_IOT": {"path": rf"{_BASE}\1_Data\raw_fingerprints\cic_iot_raw_features.csv", "min_samples": 5, "max_samples": 500},
}
TF_OUTPUT_ROOT = os.path.join(globals().get("OUTPUT_DIR", rf"{_BASE}\Resultados_Consolidados"), "Top_Features_All_Experiments")
os.makedirs(TF_OUTPUT_ROOT, exist_ok=True)
TF_EXCEL_PATH = os.path.join(TF_OUTPUT_ROOT, "Top_Features_All_Experiments.xlsx")


# --------------------------------- HELPERS -----------------------------------
def tf_show(obj):
    (display if "display" in globals() else print)(obj)

def tf_tag(name):                         # file-system safe experiment name
    return name.replace("*", "_ALL").replace("+", "_")

def tf_family(feature):                   # 'ja4ts_mss' -> 'ja4ts'
    return feature.split("_")[0]

def tf_to_numeric(series):                # tolerates True/False flags
    text = series.astype(str).str.strip().str.lower().replace({"true": "1", "false": "0"})
    return pd.to_numeric(text, errors="coerce")

def tf_clean(raw, families, features, min_samples, max_samples):
    """Same pipeline as Section 1: valid signatures -> min class size -> seeded cap -> numeric/categorical cleanup."""
    info = {"Raw Samples": len(raw)}
    valid = pd.Series(True, index=raw.index)
    for column in families:                               # every family of the experiment must be usable
        values = raw[column].fillna("").astype(str).str.strip().str.lower()
        valid &= ~values.isin(TF_INVALID_TOKENS)
    df = raw.loc[valid].copy()
    info["Valid Samples"] = len(df)

    counts = df[TF_TARGET].value_counts()
    df = df[df[TF_TARGET].isin(counts[counts >= min_samples].index)].copy()
    if max_samples:
        rng = np.random.default_rng(42)
        df = (df.assign(_r=rng.random(len(df))).sort_values([TF_TARGET, "_r"])
                .groupby(TF_TARGET, group_keys=False).head(max_samples).drop(columns="_r").reset_index(drop=True))
    info["Filtered Samples"] = len(df)

    numeric_cols = [c for c in features if c in TF_NUMERIC]
    categorical_cols = [c for c in features if c in TF_CATEGORICAL]
    for column in numeric_cols:
        df[column] = tf_to_numeric(df[column])
    df = df.dropna(subset=numeric_cols).reset_index(drop=True)
    info["Dropped (non-numeric)"] = info["Filtered Samples"] - len(df)
    for column in [TF_TARGET] + categorical_cols:
        df[column] = df[column].fillna("unknown").astype(str).str.strip().str.lower()
    return df, info

def tf_split(df):
    train_parts, test_parts = [], []
    for device in df[TF_TARGET].unique():
        sub = df[df[TF_TARGET] == device]
        if len(sub) < 2:
            train_parts.append(sub); continue
        tr, ts = train_test_split(sub, test_size=TF_TEST_SIZE, random_state=TF_SPLIT_SEED, shuffle=True)
        train_parts.append(tr); test_parts.append(ts)
    return pd.concat(train_parts, ignore_index=True), pd.concat(test_parts, ignore_index=True)

def tf_design(df_train, df_test, features):
    """Numeric fields as-is + one-hot 'field=value' columns, aligned between train and test."""
    num = [c for c in features if c in TF_NUMERIC]
    cat = [c for c in features if c in TF_CATEGORICAL]
    parts_tr, parts_ts = [df_train[num].reset_index(drop=True)], [df_test[num].reset_index(drop=True)]
    if cat:
        c_tr = pd.get_dummies(df_train[cat], dtype=np.int8, prefix_sep="=")
        c_ts = pd.get_dummies(df_test[cat], dtype=np.int8, prefix_sep="=")
        cols = sorted(set(c_tr.columns) | set(c_ts.columns))
        parts_tr.append(c_tr.reindex(columns=cols, fill_value=0).reset_index(drop=True))
        parts_ts.append(c_ts.reindex(columns=cols, fill_value=0).reset_index(drop=True))
    return pd.concat(parts_tr, axis=1), pd.concat(parts_ts, axis=1)

def tf_group_importance(columns, importances):
    frame = pd.DataFrame({"feature": columns, "importance": importances})
    frame["grouped_feature"] = frame["feature"].str.split("=", n=1).str[0]
    grouped = (frame.groupby("grouped_feature", as_index=False)["importance"].sum()
                    .sort_values("importance", ascending=False).reset_index(drop=True))
    grouped["cumulative_importance"] = grouped["importance"].cumsum()
    return grouped

def tf_bootstrap_ci(y_true, y_pred, alpha=0.05):
    rng, scores, n = np.random.default_rng(42), [], len(y_true)
    for _ in range(TF_N_BOOTSTRAPS):
        idx = rng.integers(0, n, n)
        if len(np.unique(y_true[idx])) < 2:
            continue
        scores.append(f1_score(y_true[idx], y_pred[idx], average="macro", zero_division=0))
    return (np.percentile(scores, 100 * alpha / 2), np.percentile(scores, 100 * (1 - alpha / 2))) if scores else (0.0, 0.0)

def tf_evaluate(model, X_test, y_test, n_classes, with_ci=True):
    labels = np.arange(n_classes)
    t0 = time.perf_counter()
    pred = model.predict(X_test)
    inference_ms = (time.perf_counter() - t0) / len(X_test) * 1000
    proba = model.predict_proba(X_test)
    top_k = lambda k: 1.0 if n_classes <= k else top_k_accuracy_score(y_test, proba, k=k, labels=labels)
    ci_low, ci_up = tf_bootstrap_ci(y_test, pred) if with_ci else (np.nan, np.nan)
    return {
        "Accuracy": accuracy_score(y_test, pred), "Top-3 Accuracy": top_k(3), "Top-5 Accuracy": top_k(5),
        "Precision (Macro)": precision_score(y_test, pred, average="macro", zero_division=0),
        "Recall (Macro)": recall_score(y_test, pred, average="macro", zero_division=0),
        "F1-Score (Macro)": f1_score(y_test, pred, average="macro", zero_division=0),
        "F1 95% CI Lower": ci_low, "F1 95% CI Upper": ci_up, "Inference Time (ms/sample)": inference_ms,
    }, pred

def tf_fit_top(df_train, df_test, y_train, ranking, k):
    fields = ranking[:k]
    X_tr, X_ts = tf_design(df_train, df_test, fields)
    model = RandomForestClassifier(**TF_RF_PARAMS)
    t0 = time.time(); model.fit(X_tr, y_train)
    return fields, X_tr, X_ts, model, time.time() - t0

def tf_paired_tests(y_true, pred_a, pred_b):
    ca, cb = (pred_a == y_true).astype(int), (pred_b == y_true).astype(int)
    both, b, c = int(((ca == 1) & (cb == 1)).sum()), int(((ca == 1) & (cb == 0)).sum()), int(((ca == 0) & (cb == 1)).sum())
    neither = int(((ca == 0) & (cb == 0)).sum())
    if b + c == 0:                                        # identical decisions: degenerate comparison
        return {"Paired t-statistic": np.nan, "Paired t p-value": np.nan, "McNemar statistic": 0.0, "McNemar p-value": 1.0,
                "All correct / Top incorrect": b, "All incorrect / Top correct": c}
    t_stat, t_p = ttest_rel(ca, cb)
    mc = mcnemar(np.array([[both, b], [c, neither]]), exact=False, correction=True)
    return {"Paired t-statistic": t_stat, "Paired t p-value": t_p, "McNemar statistic": mc.statistic, "McNemar p-value": mc.pvalue,
            "All correct / Top incorrect": b, "All incorrect / Top correct": c}

def tf_finish(fig, folder, name):
    for ext in ("png", "pdf"):
        fig.savefig(os.path.join(folder, f"{name}.{ext}"), dpi=300, bbox_inches="tight")
    if TF_SHOW_FIGURES:
        plt.show()
    plt.close(fig)

def tf_plot_importance(grouped, k, title, folder, name):
    shown = grouped.head(20).sort_values("importance")    # at most 20 bars (JA4* has 33 fields)
    fig, axes = plt.subplots(1, 2, figsize=(20, max(6, 0.35 * len(shown) + 2)))
    colors = ["#E45756" if f in set(grouped["grouped_feature"].head(k)) else "#4C78A8" for f in shown["grouped_feature"]]
    axes[0].barh(shown["grouped_feature"], shown["importance"], color=colors)
    axes[0].set_title(f"{title}\nImportance by original field (red = kept in Top {k})", fontsize=13, fontweight="bold")
    axes[0].set_xlabel("Summed importance", fontsize=12)
    axes[1].plot(range(1, len(grouped) + 1), grouped["cumulative_importance"], color="#F58518", linewidth=2, marker="o")
    axes[1].axhline(0.8, color="#54A24B", linestyle="--", label="80% cumulative")
    axes[1].axvline(k, color="#E45756", linestyle=":", label=f"Top {k} cut-off")
    axes[1].set_title("Cumulative importance", fontsize=13, fontweight="bold")
    axes[1].set_xlabel("Number of original fields", fontsize=12); axes[1].set_ylabel("Cumulative importance", fontsize=12)
    axes[1].grid(alpha=0.3); axes[1].legend()
    fig.tight_layout(); tf_finish(fig, folder, name)

def tf_plot_comparison(m_all, m_top, k, n_all, title, folder, name):
    groups = [("Test metrics", ["Accuracy", "Precision (Macro)", "Recall (Macro)", "F1-Score (Macro)"], ["Accuracy", "Precision", "Recall", "F1"]),
              ("Top-k accuracy", ["Accuracy", "Top-3 Accuracy", "Top-5 Accuracy"], ["Top-1", "Top-3", "Top-5"])]
    fig, axes = plt.subplots(1, 2, figsize=(18, 6)); width = 0.35
    for ax, (sub_title, cols, names) in zip(axes, groups):
        x = np.arange(len(cols)); va = [m_all[c] for c in cols]; vt = [m_top[c] for c in cols]
        ax.bar(x - width / 2, va, width, label=f"All decomposed ({n_all} fields)", color="#4C78A8", edgecolor="black")
        ax.bar(x + width / 2, vt, width, label=f"Top {k} fields", color="#F58518", edgecolor="black")
        for i in range(len(cols)):
            ax.text(x[i] - width / 2, va[i] + 0.015, f"{va[i]:.4f}", ha="center", fontsize=9)
            ax.text(x[i] + width / 2, vt[i] + 0.015, f"{vt[i]:.4f}", ha="center", fontsize=9)
        ax.set_xticks(x); ax.set_xticklabels(names, fontsize=11); ax.set_ylim(0, 1.12); ax.grid(axis="y", alpha=0.3)
        ax.set_title(f"{sub_title}", fontsize=13, fontweight="bold"); ax.legend(loc="lower right")
    fig.suptitle(title, fontsize=14, fontweight="bold"); fig.tight_layout(); tf_finish(fig, folder, name)


# ---------------------------------- MAIN LOOP ---------------------------------
tf_results, tf_importance, tf_selected, tf_stats, tf_status, tf_sweep = [], [], [], [], [], []
warnings.filterwarnings("ignore", category=RuntimeWarning)

for dataset_key, config in TF_DATASETS.items():
    if not os.path.exists(config["path"]):
        print(f"[SKIP] {dataset_key}: file not found -> {config['path']}")
        continue
    header = set(pd.read_csv(config["path"], dtype=str, nrows=0).columns)
    needed = {TF_TARGET} | {c for fams in TF_EXPERIMENTS.values() for c in fams} | set(TF_ALL_FEATURES)
    raw_all = pd.read_csv(config["path"], dtype=str, low_memory=False, usecols=sorted(needed & header))

    for exp_name, families in TF_EXPERIMENTS.items():
        features = [f for f in TF_ALL_FEATURES if tf_family(f) in families]
        missing = [c for c in families + features if c not in header]
        status = {"Dataset": dataset_key, "Experiment": exp_name, "Fields": len(features)}
        if missing:
            status["Status"] = f"SKIPPED: missing columns {missing}"
            tf_status.append(status); print(f"[SKIP] {dataset_key} | {exp_name}: missing {missing}"); continue

        df, info = tf_clean(raw_all, families, features, config["min_samples"], config["max_samples"])
        if df[TF_TARGET].nunique() < 2:
            status.update(info); status["Status"] = "SKIPPED: fewer than 2 classes after cleaning"
            tf_status.append(status); print(f"[SKIP] {dataset_key} | {exp_name}: <2 classes"); continue

        df_train, df_test = tf_split(df)
        encoder = LabelEncoder()
        y_train = encoder.fit_transform(df_train[TF_TARGET]); y_test = encoder.transform(df_test[TF_TARGET])
        n_classes = len(encoder.classes_)

        # Step 1: full decomposed model + grouped importance (training split only).
        X_tr_all, X_ts_all = tf_design(df_train, df_test, features)
        rf_all = RandomForestClassifier(**TF_RF_PARAMS)
        t0 = time.time(); rf_all.fit(X_tr_all, y_train); fit_all = time.time() - t0
        grouped = tf_group_importance(X_tr_all.columns, rf_all.feature_importances_)

        n_fields = len(features)
        ranking = grouped["grouped_feature"].tolist()
        m_all, pred_all = tf_evaluate(rf_all, X_ts_all, y_test, n_classes)
        fixed_k = max(1, min(TF_TOP_K_PER_EXPERIMENT.get(exp_name, n_fields // 2), n_fields - 1))

        # Step 2a: k-sweep. Smallest k such that it and every larger swept k are NOT significantly worse
        # than the full model (significantly worse = McNemar p < alpha and more errors than the full model).
        auto_k = None
        if TF_RUN_K_SWEEP:
            sweep_rows = []
            for k_try in sorted({k for k in TF_K_SWEEP if k < n_fields} | {fixed_k}):
                _, X_tr_k, X_ts_k, model_k, fit_k = tf_fit_top(df_train, df_test, y_train, ranking, k_try)
                m_k, pred_k = tf_evaluate(model_k, X_ts_k, y_test, n_classes, with_ci=False)
                tests = tf_paired_tests(y_test, pred_all, pred_k)
                worse = bool(tests["All correct / Top incorrect"] > tests["All incorrect / Top correct"]
                             and tests["McNemar p-value"] < TF_ALPHA)
                sweep_rows.append({"Dataset": dataset_key, "Experiment": exp_name, "k": k_try, "Fields (all)": n_fields,
                                   "One-hot columns": X_tr_k.shape[1], "Training Time (s)": fit_k,
                                   **{c: m_k[c] for c in ["Accuracy", "Top-3 Accuracy", "Top-5 Accuracy", "Precision (Macro)",
                                                          "Recall (Macro)", "F1-Score (Macro)"]},
                                   "McNemar p-value": tests["McNemar p-value"], "Significantly worse than all": worse,
                                   "Selected (auto)": False, "Is fixed k": k_try == fixed_k})
            for row in reversed(sweep_rows):              # walk from the largest k downwards
                if row["Significantly worse than all"]:
                    break
                auto_k = row["k"]
            for row in sweep_rows:
                row["Selected (auto)"] = row["k"] == auto_k
            tf_sweep.extend(sweep_rows)

        if TF_PRIMARY_K_MODE == "auto" and auto_k is not None:
            k, k_source = auto_k, "auto"
        else:
            k, k_source = fixed_k, ("fixed (auto unavailable)" if TF_PRIMARY_K_MODE == "auto" else "fixed")

        # Step 2b: primary comparison with k fields (same split and hyperparameters as the full model).
        top_fields, X_tr_top, X_ts_top, rf_top, fit_top = tf_fit_top(df_train, df_test, y_train, ranking, k)
        m_top, pred_top = tf_evaluate(rf_top, X_ts_top, y_test, n_classes)

        base = {"Dataset": dataset_key, "Experiment": exp_name, "Classes": n_classes,
                "Train Samples": len(df_train), "Test Samples": len(df_test)}
        tf_results.append({**base, "Model": "All decomposed", "Fields": n_fields, "One-hot columns": X_tr_all.shape[1],
                           "Training Time (s)": fit_all, **m_all})
        tf_results.append({**base, "Model": f"Top {k}", "Fields": k, "One-hot columns": X_tr_top.shape[1],
                           "Training Time (s)": fit_top, **m_top})
        tf_importance.append(grouped.assign(Dataset=dataset_key, Experiment=exp_name))
        tf_selected.extend({"Dataset": dataset_key, "Experiment": exp_name, "Rank": i + 1, "Field": f} for i, f in enumerate(top_fields))
        tf_stats.append({"Dataset": dataset_key, "Experiment": exp_name, **tf_paired_tests(y_test, pred_all, pred_top)})
        status.update(info); status.update({"Status": "OK", "Classes": n_classes, "Fixed k": fixed_k,
                                            "Auto k (min not worse)": auto_k, "Top-k used": k, "k source": k_source})
        tf_status.append(status)
        print(f"[OK] {dataset_key:8s} | {exp_name:22s} | classes={n_classes:3d} | fields {n_fields:2d} | "
              f"k fixed={fixed_k} auto={auto_k} used={k} | F1 all={m_all['F1-Score (Macro)']:.4f} top={m_top['F1-Score (Macro)']:.4f}")

        folder = os.path.join(TF_OUTPUT_ROOT, tf_tag(exp_name)); os.makedirs(folder, exist_ok=True)
        title = f"{dataset_key} | {exp_name}"
        tf_plot_importance(grouped, k, title, folder, f"{dataset_key}_{tf_tag(exp_name)}_feature_importance")
        tf_plot_comparison(m_all, m_top, k, n_fields, title, folder, f"{dataset_key}_{tf_tag(exp_name)}_all_vs_top{k}")


# ------------------------------ CONSOLIDATED OUTPUT ---------------------------
df_tf_results = pd.DataFrame(tf_results)
df_tf_importance = pd.concat(tf_importance, ignore_index=True)[["Dataset", "Experiment", "grouped_feature", "importance", "cumulative_importance"]]
df_tf_selected, df_tf_stats, df_tf_status = pd.DataFrame(tf_selected), pd.DataFrame(tf_stats), pd.DataFrame(tf_status)

print("\nRUN STATUS"); tf_show(df_tf_status)
print("\nRESULTS: ALL DECOMPOSED vs TOP FIELDS"); tf_show(df_tf_results)

metric_cols = ["Accuracy", "Top-3 Accuracy", "Top-5 Accuracy", "Precision (Macro)", "Recall (Macro)", "F1-Score (Macro)"]
df_tf_delta = (df_tf_results.assign(_top=df_tf_results["Model"].ne("All decomposed"))
               .groupby(["Dataset", "Experiment", "_top"], sort=False)[metric_cols].first().unstack("_top"))
df_tf_delta = (df_tf_delta.xs(True, axis=1, level="_top") - df_tf_delta.xs(False, axis=1, level="_top")).add_prefix("Delta ").reset_index()
print("\nDIFFERENCE (Top - All decomposed)"); tf_show(df_tf_delta)
print("\nPAIRED TESTS (same test rows)"); tf_show(df_tf_stats)

# One summary figure per dataset: macro F1 of All vs Top for every experiment.
for dataset_key in df_tf_results["Dataset"].unique():
    sub = df_tf_results[df_tf_results["Dataset"] == dataset_key]
    names = list(dict.fromkeys(sub["Experiment"])); x = np.arange(len(names)); width = 0.38
    f_all = [sub[(sub["Experiment"] == n) & (sub["Model"] == "All decomposed")]["F1-Score (Macro)"].iloc[0] for n in names]
    f_top = [sub[(sub["Experiment"] == n) & (sub["Model"] != "All decomposed")]["F1-Score (Macro)"].iloc[0] for n in names]
    fig, ax = plt.subplots(figsize=(14, 6))
    ax.bar(x - width / 2, f_all, width, label="All decomposed fields", color="#4C78A8", edgecolor="black")
    ax.bar(x + width / 2, f_top, width, label="Top fields", color="#F58518", edgecolor="black")
    for i in range(len(names)):
        ax.text(x[i] - width / 2, f_all[i] + 0.01, f"{f_all[i]:.3f}", ha="center", fontsize=9)
        ax.text(x[i] + width / 2, f_top[i] + 0.01, f"{f_top[i]:.3f}", ha="center", fontsize=9)
    ax.set_xticks(x); ax.set_xticklabels(names, fontsize=11); ax.set_ylim(0, 1.1); ax.set_ylabel("Macro F1", fontsize=12)
    ax.set_title(f"{dataset_key}: Macro F1, all decomposed fields vs top fields, by experiment", fontsize=13, fontweight="bold")
    ax.grid(axis="y", alpha=0.3); ax.legend(); fig.tight_layout()
    tf_finish(fig, TF_OUTPUT_ROOT, f"{dataset_key}_summary_f1_all_vs_top")

# k-sweep: macro F1 vs number of kept fields (dashed = full model, star = minimum k not significantly worse).
df_tf_sweep = pd.DataFrame(tf_sweep)
if not df_tf_sweep.empty:
    print("\nK-SWEEP (Significantly worse = McNemar p < alpha and more errors than the full model)"); tf_show(df_tf_sweep)
    print("\nRECOMMENDED k PER EXPERIMENT"); tf_show(df_tf_status[df_tf_status["Status"] == "OK"][["Dataset", "Experiment", "Fields", "Fixed k", "Auto k (min not worse)", "Top-k used", "k source"]])
    cmap = plt.get_cmap("tab10")
    for dataset_key in df_tf_sweep["Dataset"].unique():
        sub = df_tf_sweep[df_tf_sweep["Dataset"] == dataset_key]
        fig, ax = plt.subplots(figsize=(14, 7))
        for i, exp_name in enumerate(dict.fromkeys(sub["Experiment"])):
            s_exp, color = sub[sub["Experiment"] == exp_name], cmap(i)
            full_f1 = df_tf_results[(df_tf_results["Dataset"] == dataset_key) & (df_tf_results["Experiment"] == exp_name)
                                    & (df_tf_results["Model"] == "All decomposed")]["F1-Score (Macro)"].iloc[0]
            ax.plot(s_exp["k"], s_exp["F1-Score (Macro)"], marker="o", color=color, label=exp_name)
            ax.axhline(full_f1, color=color, linestyle="--", alpha=0.4)
            chosen = s_exp[s_exp["Selected (auto)"]]
            if len(chosen):
                ax.scatter(chosen["k"], chosen["F1-Score (Macro)"], marker="*", s=350, color=color, edgecolor="black", zorder=5)
        ax.set_xlabel("Number of original fields kept (k)", fontsize=12); ax.set_ylabel("Macro F1", fontsize=12)
        ax.set_title(f"{dataset_key}: Macro F1 vs k  (dashed = all fields, star = minimum k not significantly worse)", fontsize=13, fontweight="bold")
        ax.grid(alpha=0.3); ax.legend(title="Experiment"); fig.tight_layout()
        tf_finish(fig, TF_OUTPUT_ROOT, f"{dataset_key}_k_sweep_f1")

with pd.ExcelWriter(TF_EXCEL_PATH, engine="openpyxl") as writer:
    df_tf_results.round(4).to_excel(writer, sheet_name="Results", index=False)
    df_tf_delta.round(4).to_excel(writer, sheet_name="Delta_Top_minus_All", index=False)
    df_tf_importance.round(6).to_excel(writer, sheet_name="Grouped_Importance", index=False)
    df_tf_selected.to_excel(writer, sheet_name="Selected_Fields", index=False)
    df_tf_stats.round(4).to_excel(writer, sheet_name="Statistical_Tests", index=False)
    df_tf_status.to_excel(writer, sheet_name="Run_Status", index=False)
    if not df_tf_sweep.empty:
        df_tf_sweep.round(4).to_excel(writer, sheet_name="K_Sweep", index=False)
print(f"\n[OK] Figures (PNG + PDF) and workbook saved in:\n{TF_OUTPUT_ROOT}")

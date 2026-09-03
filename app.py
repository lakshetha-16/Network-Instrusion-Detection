import json
import io
import joblib
import numpy as np
import pandas as pd
import streamlit as st
import tensorflow as tf
import matplotlib.pyplot as plt


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="NetGuard AI | Intrusion Detection",
    page_icon="🛡️",
    layout="wide"
)


# ============================================================
# CUSTOM CSS
# ============================================================

# ============================================================
# CUSTOM CSS
# ============================================================

st.markdown(
    """
    <style>

        /* Main dark background */
        .stApp {
            background-color: #0B1220;
        }

        /* Main title */
        .main-title {
            font-size: 42px;
            font-weight: 700;
            margin-bottom: 0;
            color: #FFFFFF;
        }

        /* Subtitle */
        .subtitle {
            font-size: 18px;
            opacity: 0.85;
            margin-top: 5px;
            margin-bottom: 30px;
            color: #E5E7EB;
        }

        /* Section headings */
        .section-title {
            font-size: 24px;
            font-weight: 600;
            margin-top: 25px;
            margin-bottom: 15px;
            color: #FFFFFF;
        }

        /* Normal status */
        .status-normal {
            padding: 18px;
            border-radius: 12px;
            background-color: rgba(0, 180, 80, 0.12);
            border: 1px solid rgba(0, 180, 80, 0.35);
            text-align: center;
            font-size: 28px;
            font-weight: 700;
            color: #FFFFFF;
        }

        /* Intrusion status */
        .status-intrusion {
            padding: 18px;
            border-radius: 12px;
            background-color: rgba(220, 50, 50, 0.12);
            border: 1px solid rgba(220, 50, 50, 0.35);
            text-align: center;
            font-size: 28px;
            font-weight: 700;
            color: #FFFFFF;
        }

    </style>
    """,
    unsafe_allow_html=True
)


# ============================================================
# MODEL PATHS
# ============================================================

MODEL_PATH = "models/network_intrusion_autoencoder.keras"
PREPROCESSOR_PATH = "models/nids_preprocessor.pkl"
THRESHOLD_PATH = "models/nids_threshold.json"


# ============================================================
# LOAD MODEL
# ============================================================

@st.cache_resource
def load_model():
    return tf.keras.models.load_model(
        MODEL_PATH,
        compile=False
    )


# ============================================================
# LOAD PREPROCESSOR
# ============================================================

@st.cache_resource
def load_preprocessor():
    return joblib.load(PREPROCESSOR_PATH)


# ============================================================
# LOAD THRESHOLD
# ============================================================

@st.cache_data
def load_threshold():
    with open(THRESHOLD_PATH, "r") as f:
        threshold_data = json.load(f)

    return threshold_data["threshold"]


# ============================================================
# LOAD EVERYTHING
# ============================================================

try:
    autoencoder = load_model()
    preprocessor = load_preprocessor()
    threshold = load_threshold()

except Exception as e:

    st.error("❌ Unable to load the trained model files.")

    st.error(
        "Please make sure the following files exist:\n\n"
        "- models/network_intrusion_autoencoder.keras\n"
        "- models/nids_preprocessor.pkl\n"
        "- models/nids_threshold.json"
    )

    st.exception(e)
    st.stop()


# ============================================================
# FEATURE DEFINITIONS
# ============================================================

categorical_features = [
    "proto",
    "service",
    "state"
]


numerical_features = [
    "dur",
    "spkts",
    "dpkts",
    "sbytes",
    "dbytes",
    "rate",
    "sload",
    "dload",
    "sloss",
    "dloss",
    "sinpkt",
    "dinpkt",
    "sjit",
    "djit",
    "swin",
    "stcpb",
    "dtcpb",
    "dwin",
    "tcprtt",
    "synack",
    "ackdat",
    "smean",
    "dmean",
    "trans_depth",
    "response_body_len",
    "ct_src_dport_ltm",
    "ct_dst_sport_ltm",
    "is_ftp_login",
    "ct_ftp_cmd",
    "ct_flw_http_mthd",
    "is_sm_ips_ports"
]


feature_columns = numerical_features + categorical_features


# ============================================================
# HEADER
# ============================================================

st.markdown(
    '<div class="main-title">🛡️ NetGuard AI</div>',
    unsafe_allow_html=True
)

st.markdown(
    '<div class="subtitle">'
    'Network Intrusion Detection using Deep Autoencoder Anomaly Detection'
    '</div>',
    unsafe_allow_html=True
)


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.header("⚙️ Detection Settings")

    st.metric(
        "Detection Threshold",
        f"{threshold:.6f}"
    )

    st.info(
        "Records with reconstruction error greater than "
        "the threshold are classified as intrusions."
    )

    st.markdown("---")

    st.header("🧠 Model Information")

    st.write("**Model:** Deep Autoencoder")

    st.write("**Input Features:** 34")

    st.write("**Encoded Dimensions:** 16")

    st.write("**Training:** Normal traffic only")

    st.write(
        "**Threshold:** 95th percentile of "
        "normal validation reconstruction errors"
    )

    st.markdown("---")

    st.header("📈 Model Performance")

    st.metric("Accuracy", "81.32%")
    st.metric("Precision", "90.73%")
    st.metric("Recall", "73.59%")
    st.metric("F1-Score", "81.27%")
    st.metric("ROC-AUC", "87.67%")


# ============================================================
# INTRODUCTION
# ============================================================

st.markdown(
    '<div class="section-title">📁 Upload Network Traffic Data</div>',
    unsafe_allow_html=True
)

st.write(
    "Upload a CSV containing network traffic records. "
    "The system reconstructs each record using the trained "
    "autoencoder. A reconstruction error above the threshold "
    "is classified as an intrusion."
)


uploaded_file = st.file_uploader(
    "Choose a CSV file",
    type=["csv"]
)


# ============================================================
# NO FILE UPLOADED
# ============================================================

if uploaded_file is None:

    st.info(
        "👆 Please upload a CSV file to start intrusion detection."
    )

    st.markdown(
        '<div class="section-title">🔍 How It Works</div>',
        unsafe_allow_html=True
    )

    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown("### 1️⃣ Upload")
        st.write(
            "Upload network traffic data in CSV format."
        )

    with col2:
        st.markdown("### 2️⃣ Analyze")
        st.write(
            "The autoencoder reconstructs every network record."
        )

    with col3:
        st.markdown("### 3️⃣ Detect")
        st.write(
            "High reconstruction error indicates a possible intrusion."
        )

    st.warning(
        "The uploaded CSV must contain all 34 required features."
    )

    st.stop()


# ============================================================
# READ CSV
# ============================================================

try:

    df = pd.read_csv(uploaded_file)

except Exception as e:

    st.error("❌ Unable to read the uploaded CSV file.")

    st.exception(e)

    st.stop()


# ============================================================
# SUCCESS MESSAGE
# ============================================================

st.success(
    f"Successfully loaded {len(df):,} network traffic records."
)


# ============================================================
# CHECK REQUIRED FEATURES
# ============================================================

missing_features = [
    feature
    for feature in feature_columns
    if feature not in df.columns
]


if missing_features:

    st.error(
        "❌ The uploaded CSV is missing required features."
    )

    st.write("Missing features:")

    st.code(
        "\n".join(missing_features)
    )

    st.stop()


# ============================================================
# PREPARE INPUT DATA
# ============================================================

X_input_df = df[feature_columns].copy()


# ============================================================
# PREPROCESS DATA
# ============================================================

try:

    X_processed = preprocessor.transform(X_input_df)

    X_processed = np.asarray(
        X_processed,
        dtype=np.float32
    )

except Exception as e:

    st.error(
        "❌ Error while preprocessing the uploaded data."
    )

    st.exception(e)

    st.stop()


# ============================================================
# AUTOENCODER RECONSTRUCTION
# ============================================================

try:

    reconstructed = autoencoder.predict(
        X_processed,
        batch_size=512,
        verbose=0
    )

except Exception as e:

    st.error(
        "❌ Error while running the autoencoder prediction."
    )

    st.exception(e)

    st.stop()


# ============================================================
# RECONSTRUCTION ERROR
# ============================================================

reconstruction_error = np.mean(
    np.square(
        X_processed - reconstructed
    ),
    axis=1
)


# ============================================================
# CLASSIFICATION
# ============================================================

predicted_label = (
    reconstruction_error > threshold
).astype(int)


predicted_class = np.where(
    predicted_label == 1,
    "Intrusion",
    "Normal"
)


# ============================================================
# CREATE RESULTS DATAFRAME
# ============================================================

results = df.copy()


results["reconstruction_error"] = reconstruction_error

results["predicted_label"] = predicted_label

results["predicted_class"] = predicted_class


# ============================================================
# DETECTION SUMMARY
# ============================================================

total_records = len(results)

intrusions = int(
    np.sum(predicted_label == 1)
)

normal_records = int(
    np.sum(predicted_label == 0)
)

intrusion_rate = (
    intrusions / total_records * 100
    if total_records > 0
    else 0
)


# ============================================================
# DETECTION SUMMARY TITLE
# ============================================================

st.markdown(
    '<div class="section-title">📊 Detection Summary</div>',
    unsafe_allow_html=True
)


# ============================================================
# SUMMARY METRICS
# ============================================================

col1, col2, col3, col4 = st.columns(4)


with col1:

    st.metric(
        "Total Records",
        f"{total_records:,}"
    )


with col2:

    st.metric(
        "Normal",
        f"{normal_records:,}"
    )


with col3:

    st.metric(
        "Intrusions",
        f"{intrusions:,}"
    )


with col4:

    st.metric(
        "Intrusion Rate",
        f"{intrusion_rate:.2f}%"
    )


# ============================================================
# OVERALL STATUS
# ============================================================

if intrusions > 0:

    st.markdown(
        f"""
        <div class="status-intrusion">
            🚨 {intrusions:,} Potential Intrusion(s) Detected
        </div>
        """,
        unsafe_allow_html=True
    )

else:

    st.markdown(
        """
        <div class="status-normal">
            ✅ No Intrusions Detected
        </div>
        """,
        unsafe_allow_html=True
    )


# ============================================================
# RECONSTRUCTION ERROR ANALYSIS
# ============================================================

st.markdown(
    '<div class="section-title">📉 Reconstruction Error Analysis</div>',
    unsafe_allow_html=True
)


col1, col2, col3 = st.columns(3)


with col1:

    st.metric(
        "Minimum Error",
        f"{reconstruction_error.min():.6f}"
    )


with col2:

    st.metric(
        "Median Error",
        f"{np.median(reconstruction_error):.6f}"
    )


with col3:

    st.metric(
        "Maximum Error",
        f"{reconstruction_error.max():.6f}"
    )


# ============================================================
# ERROR HISTOGRAM
# ============================================================

fig, ax = plt.subplots(
    figsize=(10, 4)
)


ax.hist(
    reconstruction_error,
    bins=50,
    alpha=0.75
)


ax.axvline(
    threshold,
    linestyle="--",
    linewidth=2,
    label=f"Threshold = {threshold:.6f}"
)


ax.set_title(
    "Distribution of Reconstruction Errors"
)

ax.set_xlabel(
    "Reconstruction Error"
)

ax.set_ylabel(
    "Number of Records"
)

ax.legend()


st.pyplot(
    fig,
    use_container_width=True
)

plt.close(fig)


# ============================================================
# PREDICTION RESULTS
# ============================================================

st.markdown(
    '<div class="section-title">📋 Prediction Results</div>',
    unsafe_allow_html=True
)


display_columns = []


# Include actual label if available
if "label" in results.columns:

    display_columns.append("label")


# Include attack category if available
if "attack_cat" in results.columns:

    display_columns.append("attack_cat")


display_columns.extend(
    [
        "reconstruction_error",
        "predicted_label",
        "predicted_class"
    ]
)


st.dataframe(
    results[display_columns],
    use_container_width=True,
    height=500
)


# ============================================================
# ATTACK CATEGORY ANALYSIS
# ============================================================

if "attack_cat" in results.columns:

    st.markdown(
        '<div class="section-title">🎯 Attack Category Analysis</div>',
        unsafe_allow_html=True
    )

    # Determine actual attack records
    if "label" in results.columns:

        attack_data = results[
            results["label"] == 1
        ].copy()

    else:

        attack_data = results[
            results["attack_cat"].astype(str).str.lower()
            != "normal"
        ].copy()


    if len(attack_data) > 0:

        category_analysis = (
            attack_data
            .groupby("attack_cat")
            .agg(
                total_samples=("attack_cat", "size"),
                detected=("predicted_label", "sum"),
                mean_error=("reconstruction_error", "mean")
            )
            .reset_index()
        )


        category_analysis["detection_rate"] = (
            category_analysis["detected"]
            / category_analysis["total_samples"]
            * 100
        )


        category_analysis = category_analysis.sort_values(
            "total_samples",
            ascending=False
        )


        st.dataframe(
            category_analysis,
            use_container_width=True
        )


    else:

        st.info(
            "No attack-category records were found in the uploaded dataset."
        )


# ============================================================
# DOWNLOAD RESULTS
# ============================================================

st.markdown(
    '<div class="section-title">📥 Export Results</div>',
    unsafe_allow_html=True
)


csv_buffer = io.StringIO()


results.to_csv(
    csv_buffer,
    index=False
)


st.download_button(
    label="⬇️ Download Prediction Results",
    data=csv_buffer.getvalue(),
    file_name="network_intrusion_predictions.csv",
    mime="text/csv"
)


# ============================================================
# FOOTER
# ============================================================

st.divider()


st.caption(
    "NetGuard AI • Network Intrusion Detection using "
    "UNSW-NB15 and Deep Autoencoder Anomaly Detection"
)
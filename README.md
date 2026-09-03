\# 🛡️ NetGuard AI



\## Network Intrusion Detection Using Deep Autoencoder Anomaly Detection



NetGuard AI is a deep learning-based network intrusion detection system that identifies potentially malicious network traffic using an \*\*Autoencoder-based anomaly detection approach\*\*.



The system learns the characteristics of normal network traffic and detects unusual records by measuring their \*\*reconstruction error\*\*. If the reconstruction error exceeds a predefined threshold, the record is classified as an \*\*intrusion/anomaly\*\*.



\---



\## 🎯 Project Objective



Traditional intrusion detection systems often rely on predefined attack signatures. NetGuard AI uses an \*\*unsupervised deep learning approach\*\*, allowing it to identify abnormal network traffic based on deviations from learned normal behavior.



\### Key objectives



\* Detect anomalous network traffic

\* Use a Deep Autoencoder for anomaly detection

\* Calculate reconstruction error for every network record

\* Automatically classify traffic as \*\*Normal\*\* or \*\*Intrusion\*\*

\* Provide an interactive Streamlit interface

\* Display detection results and summary statistics



\---



\## 🧠 How It Works



The system follows these major steps:



```text

Network Traffic CSV

&#x20;       ↓

Data Preprocessing

&#x20;       ↓

Feature Transformation

&#x20;       ↓

Trained Deep Autoencoder

&#x20;       ↓

Reconstruction

&#x20;       ↓

Reconstruction Error

&#x20;       ↓

Compare with Threshold

&#x20;       ↓

Normal / Intrusion

```



\### Autoencoder Approach



An autoencoder consists of two major components:



\* \*\*Encoder\*\* – compresses the input features into a lower-dimensional representation.

\* \*\*Decoder\*\* – reconstructs the original input from the encoded representation.



The model is trained to reconstruct normal network traffic accurately.



For each new record:



```text

Reconstruction Error = Difference between

Original Input and Reconstructed Input

```



If:



```text

Reconstruction Error ≤ Threshold

```



the record is classified as:



\*\*Normal\*\*



If:



```text

Reconstruction Error > Threshold

```



the record is classified as:



\*\*Intrusion\*\*



\---



\## 📊 Input Data



NetGuard AI accepts a \*\*CSV file containing network traffic records\*\*.



The uploaded dataset should contain the network traffic features expected by the trained preprocessing pipeline.



Example:



```csv

feature\_1,feature\_2,feature\_3,feature\_4

0.12,0.45,0.31,0.72

0.21,0.39,0.28,0.61

0.91,0.87,0.95,0.99

```



\---



\## 🚀 Features



\### 📁 CSV Upload



Upload network traffic data directly through the Streamlit interface.



\### 🤖 Deep Autoencoder Detection



Uses a trained neural-network autoencoder to identify anomalous traffic.



\### 📈 Reconstruction Error



Calculates the reconstruction error for each input record.



\### 🚨 Intrusion Classification



Records are classified into:



\* 🟢 Normal

\* 🔴 Intrusion



\### 📊 Detection Summary



The application displays:



\* Total records

\* Normal records

\* Intrusion records

\* Detection statistics



\### 🖥️ Interactive Web Interface



Built using Streamlit for easy demonstration and testing.



\---



\## 🛠️ Technologies Used



| Technology         | Purpose                       |

| ------------------ | ----------------------------- |

| Python             | Core programming language     |

| TensorFlow / Keras | Deep learning and Autoencoder |

| Pandas             | Data processing               |

| NumPy              | Numerical computation         |

| Scikit-learn       | Data preprocessing            |

| Streamlit          | Interactive web application   |

| Joblib             | Preprocessor serialization    |

| JSON               | Threshold configuration       |

| Git / GitHub       | Version control               |



\---



\## 📁 Project Structure



```text

Network-Intrusion-Detection/

│

├── app.py

├── requirements.txt

├── README.md

├── .gitignore

│

├── models/

│   ├── network\_intrusion\_autoencoder.keras

│   ├── nids\_preprocessor.pkl

│   └── nids\_threshold.json

│

├── screenshots/

│   ├── Screenshot 2026-09-03 220505.png

│   ├── Screenshot 2026-09-03 221717.png

│   ├── Screenshot 2026-09-03 221729.png

│   ├── Screenshot 2026-09-03 221745.png

│   ├── Screenshot 2026-09-03 221804.png

│   ├── Screenshot 2026-09-03 221827.png

│   ├── Screenshot 2026-09-03 221844.png

│   └── Screenshot 2026-09-03 221945.png

│

└── demo/

&#x20;   └── Demo video

```



> The demo video is kept locally for demonstration purposes and is not included in the GitHub repository because of its large file size.



\---



\## ⚙️ Installation



\### 1. Clone the repository



```bash

git clone https://github.com/lakshetha-16/Network-Instrusion-Detection.git

```



\### 2. Navigate to the project



```bash

cd Network-Intrusion-Detection

```



\### 3. Create a virtual environment



```bash

python -m venv venv

```



\### 4. Activate the virtual environment



\#### Windows



```bash

venv\\Scripts\\activate

```



\### 5. Install dependencies



```bash

pip install -r requirements.txt

```



\---



\## ▶️ Run the Application



Start the Streamlit application using:



```bash

streamlit run app.py

```



The application will open in your browser.



\---



\## 🔍 Detection Methodology



The trained Autoencoder reconstructs each network traffic record.



The reconstruction error is calculated using the difference between the original and reconstructed feature values.



The trained threshold stored in:



```text

models/nids\_threshold.json

```



is used to determine whether a record should be considered anomalous.



\### Classification



| Reconstruction Error       | Classification |

| -------------------------- | -------------- |

| Below / equal to threshold | 🟢 Normal      |

| Above threshold            | 🔴 Intrusion   |



\---



\## 📸 Screenshots



The `screenshots/` folder contains screenshots demonstrating the NetGuard AI interface and its intrusion detection workflow.



\---



\## 🎥 Demo



A demonstration video showing the NetGuard AI application workflow is maintained locally in the project's `demo/` folder.



The video is not committed to GitHub because of its large file size.



\---



\## 🔮 Future Enhancements



Possible future improvements include:



\* Real-time network traffic monitoring

\* Integration with packet-capture tools

\* Support for additional intrusion datasets

\* Attack-type classification

\* Real-time anomaly visualization

\* Improved model architectures

\* Cloud deployment

\* Security alert notifications

\* Model performance monitoring



\---



\## 🎓 Project Type



\*\*Deep Learning Project\*\*



\*\*Domain:\*\* Cybersecurity / Network Security / Anomaly Detection



\*\*Model:\*\* Deep Autoencoder



\*\*Application:\*\* Network Intrusion Detection



\---



\## 👩‍💻 Author



\*\*Lakshetha S\*\*



B.Tech – Artificial Intelligence and Data Science



\---



\## ⭐ Project Summary



NetGuard AI demonstrates how \*\*Deep Learning and Autoencoder-based anomaly detection\*\* can be applied to cybersecurity to identify unusual network traffic.



The project combines:



\*\*Deep Learning + Anomaly Detection + Cybersecurity + Streamlit\*\*



to provide an interactive network intrusion detection system.




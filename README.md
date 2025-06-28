# 🛡️ DDoS Attack Detection Using Machine Learning

This project applies machine learning techniques to detect Distributed Denial of Service (DDoS) attacks in real-time using real-world network traffic data. The study compares the performance of four popular ML algorithms: Decision Tree, Logistic Regression, Naïve Bayes, and Random Forest.

## 📌 Features

- Real-time DDoS attack detection
- Dataset preprocessing and feature engineering
- Comparison of multiple ML models
- Evaluation using accuracy, precision, recall, and F1-score
- Visualization of ROC curves

## 🧠 Algorithms Used

- Decision Tree  
- Logistic Regression  
- Naïve Bayes  
- Random Forest

## 📁 Dataset

The dataset used contains labeled network traffic representing both normal and DDoS behavior. It includes features like:
- IP address
- Protocol type
- Packet size
- Timestamp
- Packets per second
- Inbound/Outbound ratios

> Note: Due to data sensitivity, the dataset may not be included. Please use your own or request access.

## ⚙️ Installation

1. Clone the repo:
   ```bash
   git clone https://github.com/yourusername/ddos-ml-detection.git
   cd ddos-ml-detection
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Run the main script:
   ```bash
   python ddos_detection.py
   ```

## 📊 Results

| Model            | Accuracy | Precision | Recall | F1-Score |
|------------------|----------|-----------|--------|----------|
| Decision Tree    | 95%      | 92%       | 93%    | 92%      |
| Logistic Regression | 93%   | 91%       | 92%    | 91%      |
| Naïve Bayes      | 90%      | 89%       | 90%    | 89%      |
| Random Forest    | **97%**  | **95%**   | **96%**| **95%**  |

## 📈 Visuals

- ROC curves plotted for all models
- Feature importance chart (Random Forest)

## 🧪 Future Work

- Implement deep learning and unsupervised models  
- Optimize for real-time deployment  
- Integrate with intrusion detection systems (IDS) or firewalls

## 📝 License

This project is licensed under the MIT License. See `LICENSE` for details.

## 🙇‍♂️ Author


Email: mohammedibrahimshawonaiub@gmail.com  
LinkedIn:  https://www.linkedin.com/in/mohammed-ibrahim-shawon-a545131b0/
GitHub: https://github.com/mohammedibrahimshawon

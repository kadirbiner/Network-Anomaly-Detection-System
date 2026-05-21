# 🛡️ Network Anomaly Detection System

Makine öğrenmesi destekli ağ anomali ve saldırı tespit sistemi.

Bu proje, network telemetry / flow verileri kullanılarak ağ trafiğinde bulunan anomali ve saldırıları tespit etmek amacıyla geliştirilmiştir. Sistem, farklı makine öğrenmesi modelleri kullanarak normal ağ trafiği ile saldırı içeren trafiği sınıflandırabilmekte ve sonuçları profesyonel bir web dashboard üzerinden canlı olarak analiz edebilmektedir.

---

# 🚀 Proje Özellikleri

- 📂 CSV yükleyerek canlı trafik analizi
- 🤖 Random Forest, SVM ve XGBoost model desteği
- 🛡️ Binary attack detection
- ⚠️ Risk seviyesi analizi
- 📊 Gerçek zamanlı saldırı oranı göstergesi
- 📈 Feature importance dashboard
- 🔍 Multi-class attack detection
- 🌐 FastAPI backend
- 🎨 React + TypeScript frontend
- 📉 Model performans karşılaştırması
- 📡 Network anomaly monitoring dashboard
- 🧠 Makine öğrenmesi tabanlı saldırı tespiti
- 📑 Threat severity sistemi
- 📋 Prediction preview sistemi
- 🎯 Model seçilebilir dashboard yapısı

---

# 🧠 Projenin Amacı

Bu projenin amacı, ağ trafiğinde bulunan anomali ve saldırıları makine öğrenmesi yöntemleri kullanarak tespit etmektir. Sistem, ağ trafiğini analiz ederek normal ve saldırı içeren davranışları ayırt edebilmekte ve güvenlik analizlerini kullanıcı dostu bir dashboard üzerinden sunmaktadır.

Proje kapsamında veri temizleme, feature engineering, model eğitimi, performans değerlendirme ve canlı tahmin sistemleri geliştirilmiştir.

Ayrıca sistem yalnızca binary classification ile sınırlı kalmayıp multi-class attack detection yaklaşımıyla saldırı türlerini de analiz edebilmektedir.

---

# 📊 Kullanılan Veri Seti

Bu projede:

```txt
UNSW-NB15

network intrusion detection veri seti kullanılmıştır.

Veri seti içerisinde:

normal ağ trafiği
saldırı trafiği
farklı saldırı kategorileri

bulunmaktadır.

⚠️ Tespit Edilebilen Saldırı Türleri
DoS
Exploits
Fuzzers
Reconnaissance
Generic
Backdoor
Shellcode
Analysis
🤖 Kullanılan Makine Öğrenmesi Modelleri
Model	Açıklama
Random Forest	Ensemble tabanlı yüksek doğruluklu saldırı tespiti
SVM	Yapısal trafik örüntülerini sınıflandırma
XGBoost	Optimize edilmiş boosted-tree saldırı tespiti
Multi-Class Random Forest	Saldırı kategorisi tahmini
📈 Sistem Özellikleri
Binary Attack Detection

Sistem, ağ trafiğini:

Normal
Attack

olarak sınıflandırabilmektedir.

Multi-Class Attack Detection

Sistem saldırı türlerini analiz ederek:

DoS
Exploits
Fuzzers
Reconnaissance
Generic

gibi saldırı kategorilerini tahmin edebilmektedir.

Risk Analizi Sistemi

Dashboard üzerinde:

LOW
MEDIUM
HIGH
CRITICAL

risk seviyeleri hesaplanmaktadır.

Feature Importance Analysis

Makine öğrenmesi modellerinin karar verirken en çok kullandığı özellikler dashboard üzerinde gösterilmektedir.

Örneğin:

ct_dst_src_ltm
sload
rate
sttl

gibi özellikler analiz edilmektedir.

Canlı Dashboard Sistemi

Kullanıcı:

CSV dosyası yükler
Model seçer
Analizi başlatır
Sonuçları canlı olarak görüntüler
🖥️ Sistem Mimarisi
CSV Upload
    ↓
FastAPI Backend
    ↓
Model Selection
(Random Forest / SVM / XGBoost)
    ↓
Prediction Engine
    ↓
Threat Analysis
    ↓
React Dashboard
🧰 Kullanılan Teknolojiler
Backend
Python
FastAPI
Scikit-learn
XGBoost
Pandas
NumPy
Joblib
Frontend
React
TypeScript
Vite
Axios
CSS
Machine Learning
Random Forest
SVM
XGBoost
Multi-Class Classification
🎨 Dashboard Özellikleri
Canlı trafik analizi
Model seçimi
Risk seviyesi analizi
Threat severity sistemi
Attack ratio monitoring
Prediction preview table
Feature importance visualization
Multi-class attack distribution
Profesyonel SOC tarzı arayüz
Responsive tasarım
Dark cyber-security dashboard
⚙️ Backend Kurulumu
Backend klasörüne gir
cd backend
Sanal ortam oluştur
python -m venv venv
Sanal ortamı aktif et
Windows
venv\Scripts\activate
Gereksinimleri yükle
pip install -r requirements.txt
Backend sunucusunu başlat
uvicorn main:app --reload --port 8000
Swagger API ekranı

Backend çalıştıktan sonra:

http://127.0.0.1:8000/docs

adresinden API test ekranına erişebilirsiniz.

🎨 Frontend Kurulumu
Frontend klasörüne gir
cd frontend
Paketleri yükle
npm install
Frontend geliştirme sunucusunu başlat
npm run dev
Frontend adresi
http://localhost:5173
📁 Model Dosyaları

Model dosyaları boyut limitleri nedeniyle GitHub reposuna eklenmemiştir.

Aşağıdaki .pkl dosyaları manuel olarak:

backend/model/

klasörüne eklenmelidir.

network_anomaly_rf_package.pkl
svm_model_package.pkl
xgboost_model_package.pkl
multi_class_attack_model_package.pkl
📊 Model Performansı

Projede kullanılan modeller yüksek doğruluk ve F1-score değerleri elde etmiştir.

Özellikle:

Random Forest
XGBoost

modelleri başarılı sonuçlar vermiştir.

⚠️ Karşılaşılan Problemler
Veri leakage problemi
Büyük veri boyutu nedeniyle performans problemleri
Frontend-backend kolon uyumsuzlukları
Farklı modellerin farklı preprocessing ihtiyaçları
Dashboard optimizasyon süreçleri
🔄 Devam Eden Çalışmalar
SHAP Explainability sistemi
Daha gelişmiş saldırı görselleştirmeleri
PDF güvenlik raporu oluşturma
Gerçek zamanlı paket analizi
Dashboard optimizasyonları
📌 Proje Durumu

✅ Veri temizleme tamamlandı
✅ Model eğitimleri tamamlandı
✅ Dashboard geliştirildi
✅ Binary classification sistemi çalışıyor
✅ Multi-model selection sistemi geliştirildi
✅ Multi-class attack detection sistemi entegre edildi
🔄 UI/UX iyileştirmeleri devam ediyor
🔄 Explainable AI (SHAP) entegrasyonu planlanıyor

👨‍💻 Grup Üyeleri
Abdulkadir Biner
Melih Tülü
Oktay Gün
📚 Akademik Amaç

Bu proje, makine öğrenmesi tabanlı ağ güvenliği sistemlerinin geliştirilmesi, saldırı tespiti, veri analizi ve gerçek zamanlı güvenlik dashboard sistemlerinin tasarlanması amacıyla geliştirilmiştir.

📷 Demo

Yakında eklenecek.

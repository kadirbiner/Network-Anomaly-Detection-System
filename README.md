# Network Anomaly Detection System

Makine öğrenmesi tabanlı ağ anomali ve saldırı tespit sistemi.

Bu proje, network telemetry / flow verileri kullanılarak ağ trafiğinde bulunan anomali ve saldırıları tespit etmek amacıyla geliştirilmiştir. Sistem, farklı makine öğrenmesi modelleri kullanarak normal ağ trafiği ile saldırı içeren trafiği sınıflandırabilmekte ve sonuçları web tabanlı bir dashboard üzerinden canlı olarak analiz edebilmektedir.

---

## Projenin Amacı

Bu projenin amacı, ağ trafiğinde bulunan anomali ve saldırıları makine öğrenmesi yöntemleri kullanarak tespit etmektir. Sistem, ağ trafiğini analiz ederek normal ve saldırı içeren davranışları ayırt edebilmekte ve güvenlik analizlerini kullanıcı dostu bir dashboard üzerinden sunmaktadır.

Proje kapsamında:
- veri temizleme
- feature engineering
- model eğitimi
- performans değerlendirme
- canlı tahmin sistemleri

geliştirilmiştir.

Ayrıca sistem yalnızca binary classification ile sınırlı kalmayıp multi-class attack detection yaklaşımıyla saldırı türlerini de analiz edebilmektedir.

---

## Kullanılan Veri Seti

Projede UNSW-NB15 veri seti kullanılmıştır.

Veri seti içerisinde:
- normal ağ trafiği
- saldırı trafiği
- farklı saldırı kategorileri

bulunmaktadır.

---

## Tespit Edilebilen Saldırı Türleri

- DoS
- Exploits
- Fuzzers
- Reconnaissance
- Generic
- Backdoor
- Shellcode
- Analysis

---

## Kullanılan Makine Öğrenmesi Modelleri

| Model | Açıklama |
|---|---|
| Random Forest | Ensemble tabanlı saldırı tespiti |
| SVM | Yapısal trafik örüntülerini sınıflandırma |
| XGBoost | Optimize edilmiş boosted-tree saldırı tespiti |
| Multi-Class Random Forest | Saldırı kategorisi tahmini |

---

## Sistem Özellikleri

- CSV yükleyerek canlı trafik analizi
- Random Forest, SVM ve XGBoost model desteği
- Binary attack detection
- Multi-class attack detection
- Risk seviyesi analizi
- Threat severity sistemi
- Attack ratio monitoring
- Feature importance analizi
- Prediction preview sistemi
- React tabanlı dashboard
- FastAPI backend mimarisi

---

## Sistem Mimarisi

```txt
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
```

---

## Kullanılan Teknolojiler

### Backend
- Python
- FastAPI
- Scikit-learn
- XGBoost
- Pandas
- NumPy
- Joblib

### Frontend
- React
- TypeScript
- Vite
- Axios
- CSS

### Machine Learning
- Random Forest
- SVM
- XGBoost
- Multi-Class Classification

---

## Dashboard Özellikleri

- Canlı trafik analizi
- Model seçimi
- Risk seviyesi analizi
- Threat severity sistemi
- Attack ratio monitoring
- Prediction preview table
- Feature importance visualization
- Multi-class attack distribution
- Responsive dashboard tasarımı

---

## Backend Kurulumu

### Backend klasörüne gir

```bash
cd backend
```

### Sanal ortam oluştur

```bash
python -m venv venv
```

### Sanal ortamı aktif et

#### Windows

```bash
venv\Scripts\activate
```

### Gereksinimleri yükle

```bash
pip install -r requirements.txt
```

### Backend sunucusunu başlat

```bash
uvicorn main:app --reload --port 8000
```

### Swagger API ekranı

Backend çalıştıktan sonra:

```txt
http://127.0.0.1:8000/docs
```

adresinden API test ekranına erişebilirsiniz.

---

## Frontend Kurulumu

### Frontend klasörüne gir

```bash
cd frontend
```

### Paketleri yükle

```bash
npm install
```

### Frontend geliştirme sunucusunu başlat

```bash
npm run dev
```

### Frontend adresi

```txt
http://localhost:5173
```

---

## Model Dosyaları

Model dosyaları boyut limitleri nedeniyle GitHub reposuna eklenmemiştir.

Aşağıdaki `.pkl` dosyaları manuel olarak:

```txt
backend/model/
```

klasörüne eklenmelidir.

```txt
network_anomaly_rf_package.pkl
svm_model_package.pkl
xgboost_model_package.pkl
multi_class_attack_model_package.pkl
```

---

## Model Performansı

Projede kullanılan modeller yüksek doğruluk ve F1-score değerleri elde etmiştir.

Özellikle:
- Random Forest
- XGBoost

modelleri başarılı sonuçlar vermiştir.

---

## Karşılaşılan Problemler

- Veri leakage problemi
- Büyük veri boyutu nedeniyle performans problemleri
- Frontend-backend kolon uyumsuzlukları
- Farklı modellerin farklı preprocessing ihtiyaçları
- Dashboard optimizasyon süreçleri

---

## Devam Eden Çalışmalar

- SHAP Explainability sistemi
- Daha gelişmiş saldırı görselleştirmeleri
- PDF güvenlik raporu oluşturma
- Gerçek zamanlı paket analizi
- Dashboard optimizasyonları

---

## Proje Durumu

- Veri temizleme tamamlandı
- Model eğitimleri tamamlandı
- Dashboard geliştirildi
- Binary classification sistemi çalışıyor
- Multi-model selection sistemi geliştirildi
- Multi-class attack detection sistemi entegre edildi
- UI/UX iyileştirmeleri devam ediyor
- Explainable AI entegrasyonu planlanıyor

---

## Grup Üyeleri

- Abdulkadir Biner
- Melih Tülü
- Oktay Gün

---

## Akademik Amaç

Bu proje, Akıllı Ağlar - SDN, Network Programlama ve Yapay Zekâ Uygulamaları Dersi kapsamında  makine öğrenmesi tabanlı ağ güvenliği sistemlerinin geliştirilmesi, saldırı tespiti, veri analizi ve gerçek zamanlı güvenlik dashboard sistemlerinin tasarlanması amacıyla geliştirilmiştir.

import { useEffect, useMemo, useState } from "react";
import axios from "axios";
import "./App.css";
import html2pdf from "html2pdf.js";

const API_BASE = "http://127.0.0.1:8000";

type ModelMetrics = {
  accuracy?: number;
  precision?: number;
  recall?: number;
  f1_score?: number;
  macro_f1?: number;
  weighted_f1?: number;
  task?: string;
};

type BinaryModelInfo = {
  key: string;
  name: string;
  description: string;
  loaded: boolean;
  performance: ModelMetrics;
};

type FeatureImportance = {
  feature: string;
  importance: number;
};

type BinaryPreviewRow = {
  prediction: number;
  prediction_label: string;
  attack_probability?: number | null;
};

type CategoryDistribution = {
  category: string;
  count: number;
  percentage: number;
};

type MultiPreviewRow = {
  attack_category_prediction: string;
  confidence?: number | null;
};

type TelemetrySummary = {
  flow_count?: number;
  total_packets?: number;
  total_bytes?: number;
  avg_packet_rate?: number;
  max_packet_rate?: number;
  avg_byte_rate?: number;
  max_byte_rate?: number;
  avg_duration?: number;
  active_connections?: number;
};

type BinaryResult = {
  success: boolean;
  task?: string;
  file_name?: string;
  source?: string;
  synthetic_profile?: string;
  total_records?: number;
  normal_count?: number;
  attack_count?: number;
  attack_ratio?: number;
  risk_level?: string;
  severity_score?: number;
  risk_message?: string;
  model_name?: string;
  model_key?: string;
  model_description?: string;
  model_metrics?: ModelMetrics;
  top_features?: FeatureImportance[];
  telemetry_summary?: TelemetrySummary;
  preview?: BinaryPreviewRow[];
  error?: string;
  missing_columns?: string[];
};

type MultiResult = {
  success: boolean;
  task?: string;
  file_name?: string;
  total_records?: number;
  attack_like_count?: number;
  attack_ratio?: number;
  risk_level?: string;
  severity_score?: number;
  risk_message?: string;
  model_name?: string;
  model_key?: string;
  model_description?: string;
  model_metrics?: ModelMetrics;
  detected_categories?: CategoryDistribution[];
  preview?: MultiPreviewRow[];
  error?: string;
  missing_columns?: string[];
};

type DetectionMode = "binary" | "multi";

const fallbackModels: BinaryModelInfo[] = [
  {
    key: "random_forest",
    name: "Random Forest",
    description: "Yüksek doğruluklu ensemble model ile güvenilir anomali tespiti.",
    loaded: true,
    performance: { accuracy: 0.9769, precision: 0.9847, recall: 0.9731, f1_score: 0.9789 },
  },
  {
    key: "svm",
    name: "SVM",
    description: "Yapılandırılmış trafik desenleri için margin tabanlı sınıflandırıcı.",
    loaded: true,
    performance: { accuracy: 0.936, f1_score: 0.9413 },
  },
  {
    key: "xgboost",
    name: "XGBoost",
    description: "Yüksek performanslı tespit için optimize edilmiş güçlendirilmiş ağaç modeli.",
    loaded: true,
    performance: { accuracy: 0.9812, precision: 0.9883, recall: 0.9769, f1_score: 0.9825 },
  },
];

const bestModelKey = "xgboost";

function formatMetric(value?: number | string) {
  if (value === undefined || value === null || value === "") return "—";
  const numberValue = Number(value);
  if (Number.isNaN(numberValue)) return String(value);
  return numberValue.toFixed(4);
}

function formatPercent(value?: number | null) {
  if (value === undefined || value === null) return "—";
  return `${(value * 100).toFixed(2)}%`;
}

function formatCompact(value?: number | null) {
  if (value === undefined || value === null) return "—";

  return new Intl.NumberFormat("tr-TR", {
    maximumFractionDigits: 2,
    notation: Math.abs(Number(value)) >= 1000000 ? "compact" : "standard",
  }).format(Number(value));
}

function openPdfReport(
  binaryResult: BinaryResult | null,
  multiResult: MultiResult | null,
  mode: DetectionMode
) {
  const result = mode === "binary" ? binaryResult : multiResult;

  if (!result || !result.success) {
    alert("PDF raporu için önce analiz yapmalısın.");
    return;
  }

  const telemetry = binaryResult?.telemetry_summary;
  const now = new Date().toLocaleString("tr-TR");

  const riskColor =
    result.risk_level === "CRITICAL"
      ? "#991b1b"
      : result.risk_level === "HIGH"
      ? "#dc2626"
      : result.risk_level === "MEDIUM"
      ? "#d97706"
      : "#16a34a";

  const reportElement = document.createElement("div");

  const cell =
    "border:1px solid #94a3b8; padding:10px 12px; color:#111827; font-size:12px; font-weight:600;";
  const head =
    "border:1px solid #94a3b8; padding:10px 12px; background:#e2e8f0; color:#0f172a; font-size:11px; font-weight:800; text-transform:uppercase; letter-spacing:.04em;";

  reportElement.innerHTML = `
    <div style="font-family: Arial, sans-serif; padding: 32px; color:#111827; background:#ffffff;">
      <div style="border-bottom:3px solid #0f172a; padding-bottom:14px; margin-bottom:22px;">
        <h1 style="margin:0; color:#0f172a; font-size:26px;">Network Anomaly Detection Report</h1>
        <p style="margin:6px 0 0; color:#334155; font-size:13px; font-weight:600;">
          Makine öğrenmesi destekli ağ anomali ve saldırı analiz raporu
        </p>
        <p style="margin:8px 0 0; color:#475569; font-size:11px;">
          Oluşturulma Tarihi: ${now}
        </p>
      </div>

      <div style="display:grid; grid-template-columns:repeat(4, 1fr); gap:10px; margin-bottom:22px;">
        <div style="border:1px solid #cbd5e1; border-radius:8px; padding:12px; background:#f8fafc;">
          <div style="font-size:10px; color:#475569; font-weight:800;">ANALİZ TÜRÜ</div>
          <div style="font-size:14px; color:#0f172a; font-weight:800; margin-top:6px;">
            ${mode === "binary" ? "Binary" : "Multi-Class"}
          </div>
        </div>

        <div style="border:1px solid #cbd5e1; border-radius:8px; padding:12px; background:#f8fafc;">
          <div style="font-size:10px; color:#475569; font-weight:800;">MODEL</div>
          <div style="font-size:14px; color:#0f172a; font-weight:800; margin-top:6px;">
            ${result.model_name || "-"}
          </div>
        </div>

        <div style="border:1px solid #cbd5e1; border-radius:8px; padding:12px; background:#f8fafc;">
          <div style="font-size:10px; color:#475569; font-weight:800;">SALDIRI ORANI</div>
          <div style="font-size:14px; color:#0f172a; font-weight:800; margin-top:6px;">
            %${result.attack_ratio || 0}
          </div>
        </div>

        <div style="border:1px solid ${riskColor}; border-radius:8px; padding:12px; background:#fff;">
          <div style="font-size:10px; color:#475569; font-weight:800;">RİSK SEVİYESİ</div>
          <div style="font-size:15px; color:${riskColor}; font-weight:900; margin-top:6px;">
            ${result.risk_level || "-"}
          </div>
        </div>
      </div>

      <h2 style="color:#0f172a; font-size:18px; margin:0 0 10px;">1. Genel Sonuç</h2>
      <table style="width:100%; border-collapse:collapse; margin-bottom:22px;">
        <tr>
          <th style="${head}">Alan</th>
          <th style="${head}">Değer</th>
        </tr>
        <tr><td style="${cell}">Analiz Türü</td><td style="${cell}">${mode === "binary" ? "Binary Anomaly Detection" : "Multi-Class Attack Detection"}</td></tr>
        <tr><td style="${cell}">Model</td><td style="${cell}">${result.model_name || "-"}</td></tr>
        <tr><td style="${cell}">Toplam Trafik</td><td style="${cell}">${result.total_records || "-"}</td></tr>
        <tr><td style="${cell}">Saldırı Oranı</td><td style="${cell}">%${result.attack_ratio || 0}</td></tr>
        <tr><td style="${cell}">Risk Seviyesi</td><td style="${cell} color:${riskColor}; font-weight:900;">${result.risk_level || "-"}</td></tr>
        <tr><td style="${cell}">Tehdit Mesajı</td><td style="${cell}">${result.risk_message || "-"}</td></tr>
      </table>

      ${
        telemetry
          ? `
          <h2 style="color:#0f172a; font-size:18px; margin:0 0 10px;">2. Telemetry Özeti</h2>
          <table style="width:100%; border-collapse:collapse; margin-bottom:22px;">
            <tr>
              <th style="${head}">Metrik</th>
              <th style="${head}">Değer</th>
            </tr>
            <tr><td style="${cell}">Flow Sayısı</td><td style="${cell}">${telemetry.flow_count ?? "-"}</td></tr>
            <tr><td style="${cell}">Toplam Paket</td><td style="${cell}">${telemetry.total_packets ?? "-"}</td></tr>
            <tr><td style="${cell}">Toplam Byte</td><td style="${cell}">${telemetry.total_bytes ?? "-"}</td></tr>
            <tr><td style="${cell}">Ortalama Packet Rate</td><td style="${cell}">${telemetry.avg_packet_rate ?? "-"}</td></tr>
            <tr><td style="${cell}">Maksimum Packet Rate</td><td style="${cell}">${telemetry.max_packet_rate ?? "-"}</td></tr>
            <tr><td style="${cell}">Ortalama Byte Rate</td><td style="${cell}">${telemetry.avg_byte_rate ?? "-"}</td></tr>
            <tr><td style="${cell}">Maksimum Byte Rate</td><td style="${cell}">${telemetry.max_byte_rate ?? "-"}</td></tr>
            <tr><td style="${cell}">Aktif Bağlantı</td><td style="${cell}">${telemetry.active_connections ?? "-"}</td></tr>
            <tr><td style="${cell}">Ortalama Süre</td><td style="${cell}">${telemetry.avg_duration ?? "-"} sn</td></tr>
          </table>
        `
          : ""
      }

      ${
        mode === "binary" && binaryResult
          ? `
          <h2 style="color:#0f172a; font-size:18px; margin:0 0 10px;">3. Binary Trafik Dağılımı</h2>
          <table style="width:100%; border-collapse:collapse; margin-bottom:22px;">
            <tr>
              <th style="${head}">Trafik Türü</th>
              <th style="${head}">Adet</th>
              <th style="${head}">Yüzde</th>
            </tr>
            <tr>
              <td style="${cell}">Normal Trafik</td>
              <td style="${cell}">${binaryResult.normal_count ?? "-"}</td>
              <td style="${cell}">%${binaryResult.total_records ? (((binaryResult.normal_count || 0) / binaryResult.total_records) * 100).toFixed(2) : "0"}</td>
            </tr>
            <tr>
              <td style="${cell}">Saldırı Trafiği</td>
              <td style="${cell}">${binaryResult.attack_count ?? "-"}</td>
              <td style="${cell}">%${binaryResult.attack_ratio ?? 0}</td>
            </tr>
          </table>
        `
          : ""
      }

      ${
        mode === "multi" && multiResult?.detected_categories
          ? `
          <h2 style="color:#0f172a; font-size:18px; margin:0 0 10px;">3. Saldırı Kategori Dağılımı</h2>
          <table style="width:100%; border-collapse:collapse; margin-bottom:22px;">
            <tr>
              <th style="${head}">Kategori</th>
              <th style="${head}">Adet</th>
              <th style="${head}">Yüzde</th>
            </tr>
            ${multiResult.detected_categories
              .map(
                (item) => `
                <tr>
                  <td style="${cell}">${item.category}</td>
                  <td style="${cell}">${item.count}</td>
                  <td style="${cell}">%${item.percentage}</td>
                </tr>
              `
              )
              .join("")}
          </table>
        `
          : ""
      }

      ${
        mode === "binary" && binaryResult?.top_features
          ? `
          <h2 style="color:#0f172a; font-size:18px; margin:0 0 10px;">4. Önemli Özellikler</h2>
          <table style="width:100%; border-collapse:collapse; margin-bottom:22px;">
            <tr>
              <th style="${head}">Özellik</th>
              <th style="${head}">Önem Değeri</th>
            </tr>
            ${binaryResult.top_features
              .map(
                (item) => `
                <tr>
                  <td style="${cell}">${item.feature}</td>
                  <td style="${cell}">${item.importance.toFixed(4)}</td>
                </tr>
              `
              )
              .join("")}
          </table>
        `
          : ""
      }

      <div style="margin-top:28px; padding-top:12px; border-top:1px solid #cbd5e1; color:#475569; font-size:10px;">
        Bu rapor, Network Anomaly Detection System tarafından otomatik olarak oluşturulmuştur.
      </div>
    </div>
  `;

  html2pdf()
    .set({
      margin: 8,
      filename: `network-anomaly-report-${mode}.pdf`,
      image: { type: "jpeg", quality: 1 },
      html2canvas: {
        scale: 2,
        backgroundColor: "#ffffff",
        useCORS: true,
      },
      jsPDF: {
        unit: "mm",
        format: "a4",
        orientation: "portrait",
      },
    })
    .from(reportElement)
    .save();
}

function App() {
  const [file, setFile] = useState<File | null>(null);
  const [detectionMode, setDetectionMode] = useState<DetectionMode>("binary");
  const [selectedModel, setSelectedModel] = useState("random_forest");
  const [binaryResult, setBinaryResult] = useState<BinaryResult | null>(null);
  const [multiResult, setMultiResult] = useState<MultiResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [backendStatus, setBackendStatus] = useState<"checking" | "online" | "offline">("checking");
  const [binaryModels, setBinaryModels] = useState<BinaryModelInfo[]>(fallbackModels);
  const [multiLoaded, setMultiLoaded] = useState(false);

  const [syntheticProfile, setSyntheticProfile] = useState("mixed");
  const [syntheticRecordCount, setSyntheticRecordCount] = useState(500);

  const currentBinaryModel = useMemo(
    () => binaryModels.find((model) => model.key === selectedModel) || binaryModels[0],
    [binaryModels, selectedModel]
  );

  const activeResult = detectionMode === "binary" ? binaryResult : multiResult;

  useEffect(() => {
    const checkHealth = async () => {
      try {
        const response = await axios.get(`${API_BASE}/health`, { timeout: 3000 });
        setBackendStatus(response.data.status === "ok" ? "online" : "offline");
        setMultiLoaded(Boolean(response.data.multi_class_loaded));
      } catch {
        setBackendStatus("offline");
      }
    };

    checkHealth();
  }, []);

  useEffect(() => {
    const fetchModels = async () => {
      try {
        const response = await axios.get(`${API_BASE}/models`, { timeout: 3000 });
        if (response.data.binary_models) {
          setBinaryModels(response.data.binary_models);
        }

        setMultiLoaded(Boolean(response.data.multi_class?.loaded));
      } catch {
        setBinaryModels(fallbackModels);
      }
    };

    fetchModels();
  }, []);

  const handleRunDetection = async () => {
    if (!file) {
      alert("Lütfen bir CSV dosyası seçin.");
      return;
    }

    const formData = new FormData();
    formData.append("file", file);

    try {
      setLoading(true);

      if (detectionMode === "binary") {
        setBinaryResult(null);

        const response = await axios.post(
          `${API_BASE}/predict-csv?model_name=${selectedModel}`,
          formData,
          { headers: { "Content-Type": "multipart/form-data" } }
        );

        setBinaryResult(response.data);
      } else {
        setMultiResult(null);

        const response = await axios.post(
          `${API_BASE}/predict-attack-category`,
          formData,
          { headers: { "Content-Type": "multipart/form-data" } }
        );

        setMultiResult(response.data);
      }
    } catch (error: any) {
      console.error(error);

      alert(
        error.code === "ERR_NETWORK"
          ? "Backend bağlantısı kurulamadı. FastAPI servisinin çalıştığından emin olun."
          : "Analiz sırasında bir hata oluştu."
      );
    } finally {
      setLoading(false);
    }
  };

  const handleRunSynthetic = async () => {
    try {
      setLoading(true);
      setDetectionMode("binary");
      setBinaryResult(null);
      setMultiResult(null);

      const response = await axios.post(
        `${API_BASE}/predict-synthetic?model_name=${selectedModel}&profile=${syntheticProfile}&record_count=${syntheticRecordCount}`
      );

      setBinaryResult(response.data);
    } catch (error: any) {
      console.error(error);

      alert(
        error.code === "ERR_NETWORK"
          ? "Backend bağlantısı kurulamadı. FastAPI servisinin çalıştığından emin olun."
          : "Sentetik trafik simülasyonu sırasında hata oluştu."
      );
    } finally {
      setLoading(false);
    }
  };

  const getRiskClass = (risk?: string) => {
    if (risk === "LOW") return "risk-low";
    if (risk === "MEDIUM") return "risk-medium";
    if (risk === "HIGH") return "risk-high";
    if (risk === "CRITICAL") return "risk-critical";
    return "";
  };

  const getSeverityLabel = (score?: number) => {
    if (score === 1) return "Düşük";
    if (score === 2) return "Orta";
    if (score === 3) return "Yüksek";
    if (score === 4) return "Kritik";
    return "—";
  };

  const attackRatio = activeResult?.success ? activeResult.attack_ratio || 0 : 0;
  const riskLevel = activeResult?.success ? activeResult.risk_level : undefined;

  return (
    <div className="page">
      <header className="hero">
        <div className="hero-left">
          <p className="eyebrow">YAPAY ZEKA DESTEKLİ GÜVENLİK SİSTEMİ</p>
          <h1>Ağ Anomali Tespit Merkezi</h1>
          <p className="subtitle">
            Makine öğrenmesi destekli sistem ile ağ trafiğinde anomali ve saldırı analizi gerçekleştirilir.
          </p>
        </div>

        <div className="hero-stats">
          <div className="hero-card">
            <span className="hero-label">Sistem Durumu</span>
            <strong className={`hero-value status-${backendStatus}`}>
              {backendStatus === "online" ? "Aktif" : backendStatus === "checking" ? "Kontrol..." : "Pasif"}
            </strong>
          </div>

          <div className="hero-card">
            <span className="hero-label">Analiz Türü</span>
            <strong className="hero-value">{detectionMode === "binary" ? "İkili" : "Çoklu Sınıf"}</strong>
          </div>

          <div className="hero-card">
            <span className="hero-label">Seçili Model</span>
            <strong className="hero-value">
              {detectionMode === "binary" ? currentBinaryModel?.name : "Saldırı Kategorisi"}
            </strong>
          </div>
        </div>
      </header>

      <main className="grid">
        <aside className="panel control-panel">
          <div className="panel-header">
            <span className="panel-icon">◈</span>
            <h2>Canlı Trafik Analizi</h2>
          </div>

          <p className="panel-copy">
            CSV flow verisi yükleyerek veya sentetik trafik oluşturarak ağ trafiğini analiz edin.
          </p>

          <div className="control-group">
            <label className="control-label">Analiz Türü</label>

            <div className="mode-toggle">
              <button
                type="button"
                className={detectionMode === "binary" ? "toggle-btn active" : "toggle-btn"}
                onClick={() => setDetectionMode("binary")}
              >
                İkili Sınıflandırma
              </button>

              <button
                type="button"
                className={detectionMode === "multi" ? "toggle-btn active" : "toggle-btn"}
                onClick={() => setDetectionMode("multi")}
              >
                Saldırı Kategorisi
              </button>
            </div>
          </div>

          {detectionMode === "binary" && (
            <div className="control-group">
              <label className="control-label">Model Seçimi</label>

              <div className="model-selector">
                {binaryModels.map((model) => (
                  <button
                    key={model.key}
                    type="button"
                    className={`model-btn ${selectedModel === model.key ? "active" : ""} ${
                      !model.loaded ? "disabled" : ""
                    }`}
                    onClick={() => model.loaded && setSelectedModel(model.key)}
                    disabled={!model.loaded}
                  >
                    <span>{model.name}</span>
                    <small>
                      F1 {formatMetric(model.performance?.f1_score)}
                      {model.key === bestModelKey ? " · Önerilen" : ""}
                      {!model.loaded ? " · Dosya eksik" : ""}
                    </small>
                  </button>
                ))}
              </div>

              <div className="model-note">{currentBinaryModel?.description}</div>
            </div>
          )}

          {detectionMode === "multi" && (
            <div className="model-note">
              Normal, Generic, Exploits, DoS, Fuzzers veya Reconnaissance gibi saldırı kategorilerini tahmin eder.
              {!multiLoaded && (
                <strong className="missing-note">
                  Çoklu sınıf model dosyası henüz yüklenmedi.
                </strong>
              )}
            </div>
          )}

          <div className="control-group">
            <label className="control-label">CSV Dosyası</label>

            <label className="file-box">
              <input
                type="file"
                accept=".csv"
                onChange={(event) => setFile(event.target.files?.[0] || null)}
              />

              <span>{file ? file.name : "CSV dosyası seç..."}</span>
            </label>
          </div>

          <button className="run-btn" onClick={handleRunDetection} disabled={loading}>
            {loading ? "Analiz ediliyor..." : "Analizi Başlat"}
          </button>

          {detectionMode === "binary" && (
            <div className="synthetic-card">
              <div className="synthetic-title">
                <span>Sentetik Trafik Simülasyonu</span>
                <small>CSV olmadan trafik üret</small>
              </div>

              <label className="control-label">Trafik Profili</label>

              <select
                className="select-input"
                value={syntheticProfile}
                onChange={(e) => setSyntheticProfile(e.target.value)}
              >
                <option value="mixed">Karışık Trafik</option>
                <option value="normal">Normal Trafik</option>
                <option value="ddos">DDoS Benzeri</option>
                <option value="port_scan">Port Scan Benzeri</option>
              </select>

              <label className="control-label">Kayıt Sayısı</label>

              <input
                className="number-input"
                type="number"
                min={20}
                max={5000}
                value={syntheticRecordCount}
                onChange={(e) => setSyntheticRecordCount(Number(e.target.value))}
              />

              <button
                className="secondary-run-btn"
                onClick={handleRunSynthetic}
                disabled={loading}
              >
                {loading ? "Simülasyon çalışıyor..." : "Sentetik Analiz Başlat"}
              </button>
            </div>
          )}

          <div className="system-card">
            <div>
              <span>Veri Türü</span>
              <strong>{binaryResult?.source === "synthetic" ? "Sentetik Flow" : "CSV Flow"}</strong>
            </div>

            <div>
              <span>Görev</span>
              <strong>{detectionMode === "binary" ? "İkili Sınıflandırma" : "Saldırı Türü Sınıflandırması"}</strong>
            </div>

            <div>
              <span>Veri Seti</span>
              <strong>UNSW-NB15</strong>
            </div>
          </div>
        </aside>

        <section className="panel result-panel">
          <div className="panel-header result-header">
            <div>
              <span className="panel-icon">▣</span>
              <h2>Analiz Sonucu</h2>
            </div>

            <div className="result-actions">
              {activeResult?.success && (
                <button
                  className="pdf-btn"
                  onClick={() => openPdfReport(binaryResult, multiResult, detectionMode)}
                >
                  PDF Raporu İndir
                </button>
              )}

              {activeResult?.success && (
                <span className={`risk-pill ${getRiskClass(riskLevel)}`}>
                  {riskLevel === "LOW"
                    ? "DÜŞÜK"
                    : riskLevel === "MEDIUM"
                    ? "ORTA"
                    : riskLevel === "HIGH"
                    ? "YÜKSEK"
                    : riskLevel === "CRITICAL"
                    ? "KRİTİK"
                    : riskLevel}
                </span>
              )}
            </div>
          </div>

          {!activeResult && (
            <div className="empty-state">
              <div className="empty-icon">◉</div>
              <p>Henüz analiz yapılmadı.</p>
              <p className="empty-hint">
                Bir model seçin, CSV dosyası yükleyin veya sentetik trafik simülasyonu başlatın.
              </p>
            </div>
          )}

          {activeResult && !activeResult.success && (
            <div className="error-box">
              <h3>Analiz Hatası</h3>
              <p>{activeResult.error}</p>

              {activeResult.missing_columns && (
                <>
                  <strong>Eksik kolonlar:</strong>

                  <ul>
                    {activeResult.missing_columns.slice(0, 30).map((column) => (
                      <li key={column}>{column}</li>
                    ))}
                  </ul>
                </>
              )}
            </div>
          )}

          {activeResult?.success && detectionMode === "binary" && binaryResult?.success && (
            <>
              <div className="metrics-grid">
                <div className="metric-card">
                  <span>Toplam Trafik</span>
                  <strong>{binaryResult.total_records}</strong>
                </div>

                <div className="metric-card safe">
                  <span>Normal Trafik</span>
                  <strong>{binaryResult.normal_count}</strong>
                </div>

                <div className="metric-card danger">
                  <span>Saldırı Trafiği</span>
                  <strong>{binaryResult.attack_count}</strong>
                </div>

                <div className={`metric-card ${getRiskClass(binaryResult.risk_level)}`}>
                  <span>Saldırı Oranı</span>
                  <strong>{binaryResult.attack_ratio}%</strong>
                </div>

                <div className={`metric-card ${getRiskClass(binaryResult.risk_level)}`}>
                  <span>Risk Seviyesi</span>
                  <strong>{binaryResult.risk_level}</strong>
                </div>

                <div className={`metric-card ${getRiskClass(binaryResult.risk_level)}`}>
                  <span>Tehdit Seviyesi</span>
                  <strong>{binaryResult.severity_score}/4</strong>
                </div>
              </div>

              <TelemetrySummaryPanel
                summary={binaryResult.telemetry_summary}
                source={binaryResult.source}
                profile={binaryResult.synthetic_profile}
              />

              <BinaryDistributionChart
                normalCount={binaryResult.normal_count || 0}
                attackCount={binaryResult.attack_count || 0}
              />

              <ThreatMonitor
                attackRatio={attackRatio}
                riskLevel={binaryResult.risk_level}
                riskMessage={binaryResult.risk_message}
                severityScore={binaryResult.severity_score}
                severityLabel={getSeverityLabel(binaryResult.severity_score)}
              />

              <div className="two-columns">
                <ModelPerformance metrics={binaryResult.model_metrics} />
                <FeatureImportance features={binaryResult.top_features || []} />
              </div>

              <div className="box table-box">
                <h3>Tahmin Önizleme</h3>

                <table>
                  <thead>
                    <tr>
                      <th>#</th>
                      <th>Tahmin</th>
                      <th>Durum</th>
                      <th>Olasılık</th>
                    </tr>
                  </thead>

                  <tbody>
                    {binaryResult.preview?.map((row, index) => (
                      <tr key={index}>
                        <td>{index + 1}</td>
                        <td className="mono">{row.prediction}</td>
                        <td>
                          <span className={row.prediction === 1 ? "badge badge-danger" : "badge badge-safe"}>
                            {row.prediction_label === "Attack" ? "Saldırı" : "Normal"}
                          </span>
                        </td>
                        <td className="mono">{formatPercent(row.attack_probability)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}

          {activeResult?.success && detectionMode === "multi" && multiResult?.success && (
            <>
              <div className="metrics-grid">
                <div className="metric-card">
                  <span>Toplam Trafik</span>
                  <strong>{multiResult.total_records}</strong>
                </div>

                <div className="metric-card danger">
                  <span>Saldırı Benzeri</span>
                  <strong>{multiResult.attack_like_count}</strong>
                </div>

                <div className={`metric-card ${getRiskClass(multiResult.risk_level)}`}>
                  <span>Risk Seviyesi</span>
                  <strong>{multiResult.risk_level}</strong>
                </div>

                <div className="metric-card">
                  <span>Model</span>
                  <strong>Saldırı Kategorisi</strong>
                </div>
              </div>

              <ThreatMonitor
                attackRatio={attackRatio}
                riskLevel={multiResult.risk_level}
                riskMessage={multiResult.risk_message}
                severityScore={multiResult.severity_score}
                severityLabel={getSeverityLabel(multiResult.severity_score)}
              />

              <AttackCategoryChart categories={multiResult.detected_categories || []} />

              <div className="two-columns">
                <div className="box">
                  <h3>Tespit Edilen Kategoriler</h3>

                  <div className="features category-list">
                    {multiResult.detected_categories?.map((item) => (
                      <div className="feature-row" key={item.category}>
                        <span className="feature-name">{item.category}</span>

                        <div className="feature-bar">
                          <div style={{ width: `${Math.min(item.percentage, 100)}%` }} />
                        </div>

                        <small className="feature-val">%{item.percentage}</small>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="box">
                  <h3>Kategori Model Bilgisi</h3>

                  <div className="model-info-list">
                    <div>
                      <span>Görev</span>
                      <strong>Çoklu Sınıf</strong>
                    </div>

                    <div>
                      <span>Model</span>
                      <strong>{multiResult.model_name}</strong>
                    </div>

                    <div>
                      <span>Saldırı Oranı</span>
                      <strong>%{multiResult.attack_ratio}</strong>
                    </div>

                    <div>
                      <span>Seviye</span>
                      <strong>{multiResult.severity_score}/4</strong>
                    </div>
                  </div>
                </div>
              </div>

              <div className="box table-box">
                <h3>Kategori Tahminleri</h3>

                <table>
                  <thead>
                    <tr>
                      <th>#</th>
                      <th>Tahmin Edilen Kategori</th>
                      <th>Güven Oranı</th>
                    </tr>
                  </thead>

                  <tbody>
                    {multiResult.preview?.map((row, index) => (
                      <tr key={index}>
                        <td>{index + 1}</td>
                        <td>
                          <span className={row.attack_category_prediction === "Normal" ? "badge badge-safe" : "badge badge-danger"}>
                            {row.attack_category_prediction}
                          </span>
                        </td>
                        <td className="mono">{formatPercent(row.confidence)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </>
          )}
        </section>
      </main>
    </div>
  );
}

function TelemetrySummaryPanel({
  summary,
  source,
  profile,
}: {
  summary?: TelemetrySummary;
  source?: string;
  profile?: string;
}) {
  if (!summary) return null;

  return (
    <div className="telemetry-box">
      <div className="telemetry-header">
        <div>
          <h3>Telemetry Özeti</h3>
          <p>Flow verisinden paket, byte, hız ve bağlantı yoğunluğu metrikleri hesaplandı.</p>
        </div>

        <span className="telemetry-source">
          {source === "synthetic" ? `Sentetik · ${profile}` : "CSV Flow"}
        </span>
      </div>

      <div className="telemetry-grid">
        <div>
          <span>Toplam Paket</span>
          <strong>{formatCompact(summary.total_packets)}</strong>
        </div>

        <div>
          <span>Toplam Byte</span>
          <strong>{formatCompact(summary.total_bytes)}</strong>
        </div>

        <div>
          <span>Ortalama Packet Rate</span>
          <strong>{formatCompact(summary.avg_packet_rate)}</strong>
        </div>

        <div>
          <span>Max Packet Rate</span>
          <strong>{formatCompact(summary.max_packet_rate)}</strong>
        </div>

        <div>
          <span>Ortalama Byte Rate</span>
          <strong>{formatCompact(summary.avg_byte_rate)}</strong>
        </div>

        <div>
          <span>Max Byte Rate</span>
          <strong>{formatCompact(summary.max_byte_rate)}</strong>
        </div>

        <div>
          <span>Aktif Bağlantı</span>
          <strong>{formatCompact(summary.active_connections)}</strong>
        </div>

        <div>
          <span>Ortalama Süre</span>
          <strong>{summary.avg_duration ?? "—"} sn</strong>
        </div>

        <div>
          <span>Flow Sayısı</span>
          <strong>{formatCompact(summary.flow_count)}</strong>
        </div>
      </div>

      <TelemetryChart summary={summary} />
    </div>
  );
}

function TelemetryChart({ summary }: { summary: TelemetrySummary }) {
  const metrics = [
    { label: "Toplam Paket", value: summary.total_packets || 0 },
    { label: "Toplam Byte", value: summary.total_bytes || 0 },
    { label: "Packet Rate", value: summary.avg_packet_rate || 0 },
    { label: "Byte Rate", value: summary.avg_byte_rate || 0 },
    { label: "Aktif Bağlantı", value: summary.active_connections || 0 },
  ];

  const maxValue = Math.max(...metrics.map((item) => item.value), 1);

  return (
    <div className="telemetry-chart">
      <h4>Telemetry Grafik Özeti</h4>

      {metrics.map((item) => (
        <div className="telemetry-chart-row" key={item.label}>
          <span>{item.label}</span>

          <div className="chart-track">
            <div
              className="chart-fill telemetry-fill"
              style={{ width: `${(item.value / maxValue) * 100}%` }}
            />
          </div>

          <strong>{formatCompact(item.value)}</strong>
        </div>
      ))}
    </div>
  );
}

function BinaryDistributionChart({
  normalCount,
  attackCount,
}: {
  normalCount: number;
  attackCount: number;
}) {
  const total = normalCount + attackCount || 1;
  const normalPercent = (normalCount / total) * 100;
  const attackPercent = (attackCount / total) * 100;

  return (
    <div className="box">
      <h3>Normal / Saldırı Dağılımı</h3>

      <div className="distribution-bars">
        <div>
          <div className="chart-label">
            <span>Normal Trafik</span>
            <strong>%{normalPercent.toFixed(2)}</strong>
          </div>

          <div className="chart-track">
            <div className="chart-fill safe-fill" style={{ width: `${normalPercent}%` }} />
          </div>
        </div>

        <div>
          <div className="chart-label">
            <span>Saldırı Trafiği</span>
            <strong>%{attackPercent.toFixed(2)}</strong>
          </div>

          <div className="chart-track">
            <div className="chart-fill danger-fill" style={{ width: `${attackPercent}%` }} />
          </div>
        </div>
      </div>
    </div>
  );
}

function AttackCategoryChart({ categories }: { categories: CategoryDistribution[] }) {
  if (!categories.length) return null;

  return (
    <div className="box">
      <h3>Saldırı Kategori Dağılım Grafiği</h3>

      <div className="category-chart">
        {categories.slice(0, 8).map((item) => (
          <div className="category-chart-row" key={item.category}>
            <span>{item.category}</span>

            <div className="chart-track">
              <div
                className={item.category === "Normal" ? "chart-fill safe-fill" : "chart-fill danger-fill"}
                style={{ width: `${Math.min(item.percentage, 100)}%` }}
              />
            </div>

            <strong>%{item.percentage}</strong>
          </div>
        ))}
      </div>
    </div>
  );
}

function ThreatMonitor({
  attackRatio,
  riskLevel,
  riskMessage,
  severityScore,
  severityLabel,
}: {
  attackRatio: number;
  riskLevel?: string;
  riskMessage?: string;
  severityScore?: number;
  severityLabel: string;
}) {
  return (
    <div className="threat-monitor">
      <div className="threat-top">
        <div>
          <h3>Gerçek Zamanlı Tehdit Analizi</h3>
          <p>{riskMessage}</p>
        </div>

        <strong className={riskLevel ? riskLevel.toLowerCase() : ""}>%{attackRatio}</strong>
      </div>

      <div className="progress-track">
        <div
          className={`progress-fill ${riskLevel ? riskLevel.toLowerCase() : ""}`}
          style={{ width: `${Math.min(attackRatio, 100)}%` }}
        />
      </div>

      <div className="severity-row">
        <span>Tehdit Seviyesi</span>
        <strong>
          {severityScore}/4 · {severityLabel}
        </strong>
      </div>
    </div>
  );
}

function ModelPerformance({ metrics }: { metrics?: ModelMetrics }) {
  return (
    <div className="box">
      <h3>Model Performansı</h3>

      <div className="mini-metrics">
        <div>
          <span>Accuracy</span>
          <strong>{formatMetric(metrics?.accuracy)}</strong>
        </div>

        <div>
          <span>Precision</span>
          <strong>{formatMetric(metrics?.precision)}</strong>
        </div>

        <div>
          <span>Recall</span>
          <strong>{formatMetric(metrics?.recall)}</strong>
        </div>

        <div>
          <span>F1 Score</span>
          <strong>{formatMetric(metrics?.f1_score)}</strong>
        </div>
      </div>
    </div>
  );
}

function FeatureImportance({ features }: { features: FeatureImportance[] }) {
  return (
    <div className="box">
      <h3>Önemli Özellikler</h3>

      <div className="features">
        {features.slice(0, 8).map((item) => (
          <div className="feature-row" key={item.feature}>
            <span className="feature-name">{item.feature}</span>

            <div className="feature-bar">
              <div style={{ width: `${Math.min(item.importance * 1000, 100)}%` }} />
            </div>

            <small className="feature-val">{item.importance.toFixed(4)}</small>
          </div>
        ))}
      </div>
    </div>
  );
}

export default App;
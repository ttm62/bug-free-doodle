import matplotlib.pyplot as plt
import numpy as np

# Cấu hình phong cách học thuật chuẩn báo cáo / luận văn
plt.rcParams["font.family"] = "sans-serif"
plt.rcParams["font.size"] = 11

# Danh sách kịch bản (đảo ngược thứ tự để "Trung bình" nằm ở trên cùng hoặc kịch bản đầu tiên ở trên)
scenarios = [
    "Russell", "Fox", "Santos", "Wardbeck", 
    "Shaw", "Harrison", "Wheeler", "Wilson", "Trung bình"
]

# Đảo ngược thứ tự để Russell nằm trên cùng, Trung bình nằm dưới cùng
scenarios = scenarios[::-1]

# Dữ liệu từ thực nghiệm 8 kịch bản (ait_ads/labels2.csv) đảo ngược theo scenarios
precision_aminer = [85.75, 88.96, 80.52, 31.80, 43.20, 93.31, 92.89, 88.63, 75.63][::-1]
precision_wazuh  = [25.77, 91.24, 11.11,  9.20, 11.11, 81.28, 78.51, 76.84, 48.13][::-1]
precision_custom = [99.40, 95.49, 91.91, 94.62, 97.76, 96.47, 98.83, 93.07, 95.94][::-1]

recall_aminer = [80.0, 90.0, 90.0, 80.0, 90.0, 90.0, 88.9, 90.0, 87.36][::-1]
recall_wazuh  = [80.0, 70.0, 90.0, 90.0, 80.0, 100.0, 88.9, 90.0, 86.11][::-1]
recall_custom = [90.0, 80.0, 80.0, 80.0, 80.0, 80.0, 77.8, 80.0, 80.98][::-1]

f1_aminer = [82.78, 89.48, 85.00, 45.51, 58.38, 91.63, 90.85, 89.31, 76.62][::-1]
f1_wazuh  = [38.98, 79.22, 19.78, 16.70, 19.52, 89.68, 83.38, 82.90, 53.77][::-1]
f1_custom = [94.47, 87.06, 85.54, 86.70, 87.99, 87.46, 87.05, 86.04, 87.79][::-1]

y = np.arange(len(scenarios))
height = 0.26

# Màu sắc chuẩn tương phản cao
c_aminer = "#4A90E2"   # Xanh dương
c_wazuh  = "#E94E77"   # Đỏ cam
c_custom = "#2ECC71"   # Xanh lá

def create_horizontal_chart(aminer_data, wazuh_data, custom_data, title, xlabel, filename):
    fig, ax = plt.subplots(figsize=(11, 7))
    
    # Vẽ thanh ngang bằng barh
    b1 = ax.barh(y + height, aminer_data, height, label="AMiner (Anomaly/Heuristic)", color=c_aminer, edgecolor="black", linewidth=0.6)
    b2 = ax.barh(y,          wazuh_data,  height, label="Wazuh (SIEM Rules)", color=c_wazuh, edgecolor="black", linewidth=0.6)
    b3 = ax.barh(y - height, custom_data, height, label="Custom Engine (Graph)", color=c_custom, edgecolor="black", linewidth=0.8)
    
    # Hiển thị số liệu % trực tiếp bên phải mỗi thanh của Custom Engine
    for rect in b3:
        w = rect.get_width()
        ax.annotate(f"{w:.1f}%",
                    xy=(w, rect.get_y() + rect.get_height() / 2),
                    xytext=(4, 0),  # 4 points horizontal offset
                    textcoords="offset points",
                    ha='left', va='center', fontsize=8.5, fontweight='bold', color="#1E824C")

    # Highlight vùng "Trung bình" (ở vị trí y = 0 vì đã đảo ngược)
    ax.axhspan(-0.5, 0.5, color="gray", alpha=0.12, label="Trung bình")

    ax.set_title(title, fontweight="bold", fontsize=13, pad=12)
    ax.set_xlabel(xlabel, fontweight="bold", labelpad=8)
    ax.set_ylabel("Kịch bản tấn công (AIT-ADS Dataset)", fontweight="bold", labelpad=8)
    ax.set_yticks(y)
    ax.set_yticklabels(scenarios, fontweight="bold")
    ax.set_xlim(0, 115)
    ax.grid(axis="x", linestyle="--", alpha=0.5)
    
    # Legend nằm ngang ở phía dưới đáy ngoài khung đồ thị
    ax.legend(
        loc="upper center",
        bbox_to_anchor=(0.5, -0.12),
        ncol=4,
        frameon=True,
        framealpha=0.95,
        edgecolor="#cccccc"
    )

    plt.tight_layout()
    plt.savefig(filename, dpi=300, bbox_inches="tight")
    plt.close(fig)
    print(f"✅ Đã lưu biểu đồ ngang: {filename}")

if __name__ == "__main__":
    # 1. Biểu đồ Precision xoay ngang
    create_horizontal_chart(
        precision_aminer, precision_wazuh, precision_custom,
        "Biểu đồ so sánh Độ chính xác (Precision) giữa các hệ thống",
        "Precision (%)",
        "chart_precision_horizontal.png"
    )

    # 2. Biểu đồ Recall xoay ngang
    create_horizontal_chart(
        recall_aminer, recall_wazuh, recall_custom,
        "Biểu đồ so sánh Độ bao phủ giai đoạn tấn công (Recall / Phase Coverage)",
        "Recall (%)",
        "chart_recall_horizontal.png"
    )

    # 3. Biểu đồ F1-Score xoay ngang
    create_horizontal_chart(
        f1_aminer, f1_wazuh, f1_custom,
        "Biểu đồ so sánh Điểm F1-Score giữa các hệ thống",
        "F1-Score (%)",
        "chart_f1_score_horizontal.png"
    )

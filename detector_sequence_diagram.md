# Sơ đồ trình tự luồng quét (Detection Flow)

Sơ đồ trình tự này mô tả luồng thực thi khi chạy công cụ ở **chế độ quét** (`-mode detect`). Nó bao gồm từ bước phân tích tập luật cho đến khi thực thi các truy vấn Cypher đệ quy và lọc trùng lặp cảnh báo.

```mermaid
sequenceDiagram
    autonumber
    
    participant User as Người dùng
    participant Main as main.go<br/>(main)
    participant Detector as detector.go<br/>(runDetectionMode)
    participant RuleLoader as Tải tập luật<br/>(loadRulesFromPath)
    participant Evaluator as Đánh giá Node<br/>(evaluateRuleTreeNode)
    participant Neo4j as Cơ sở dữ liệu Neo4j
    participant Cache as Bộ đệm cảnh báo<br/>(Alert Cache)
    participant Output as File cảnh báo JSONL

    User->>Main: Chạy công cụ với `-mode detect`
    Main->>Detector: Gọi runDetectionMode(...)
    
    Detector->>RuleLoader: Đọc và phân tích file luật (*.json)
    RuleLoader-->>Detector: Trả về mảng các luật (DetectionRule)
    
    Detector->>Output: Tạo / Mở file alerts.jsonl
    
    loop Duyệt từng luật đã tải
        Detector->>Evaluator: Đánh giá Node gốc<br/>evaluateRuleTreeNode(rule.Tree)
        
        note over Evaluator: Duyệt đệ quy cây quyết định
        
        loop Gọi đệ quy cho Node hiện tại
            Evaluator->>Neo4j: Gửi truy vấn (Cypher) của Node
            Neo4j-->>Evaluator: Trả về danh sách các kết quả khớp
            
            loop Duyệt từng kết quả
                Evaluator->>Evaluator: Gộp dữ liệu kết quả với Node cha
                
                alt Nếu Mức độ (Severity) thỏa mãn & Node cho phép cảnh báo
                    Evaluator->>Cache: Sinh mã Hash (generateAlertHash)
                    Evaluator->>Cache: Kiểm tra trùng lặp (isDuplicateAlert)
                    
                    alt Không trùng lặp
                        Cache-->>Evaluator: false (Cảnh báo mới)
                        Evaluator->>Evaluator: Định dạng tin nhắn cảnh báo
                        Evaluator->>Output: Ghi cảnh báo ra định dạng JSONL
                    else Trùng lặp
                        Cache-->>Evaluator: true (Bỏ qua cảnh báo)
                    end
                end
                
                loop Duyệt các Node con của Node hiện tại
                    Evaluator->>Evaluator: Gọi đệ quy cho lớp tiếp theo<br/>evaluateRuleTreeNode(depth+1)
                end
            end
        end
    end
    
    Detector->>Output: Xả bộ đệm (Flush) và Đóng file
    Detector-->>User: In tổng kết (Tổng số cảnh báo đã sinh)
```

## Các cơ chế chính:
1. **Phân tích tập luật:** Các luật (Rules) là những file JSON chứa truy vấn Cypher được tổ chức dưới dạng cây quyết định (Cha -> Con -> Cháu).
2. **Đánh giá đệ quy:** Những kết quả khớp từ Node cha sẽ được truyền xuống làm tham số (`params`) cho các câu truy vấn Cypher của Node con. Cơ chế này cho phép theo dõi trạng thái xuyên suốt của một chuỗi tấn công (kill-chain).
3. **Bộ đệm cảnh báo (Chống trùng lặp):** Một mã Hash được sinh ra dựa trên ID của Luật, ID của Node và chi tiết của truy vấn (`details`). Nếu hệ thống bắt gặp một Hash giống hệt trong khoảng thời gian hiệu lực (TTL - mặc định 24h), cảnh báo đó sẽ bị loại bỏ để tránh gây tràn ngập màn hình (alert flooding).

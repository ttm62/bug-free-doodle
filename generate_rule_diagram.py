import json
import glob
import os
import re
import argparse

def extract_query_logic(query):
    if not query:
        return ""
    
    lines = []
    # Extract MATCH
    if "MATCH " in query:
        match_part = query.split("MATCH ")[1].split(" WHERE")[0].split(" RETURN")[0].split(" WITH")[0].strip()
        match_part = match_part.replace('"', "'")
        lines.append(f"🔍 MẪU: {match_part}")
        
    # Extract WHERE
    if "WHERE " in query:
        where_part = query.split("WHERE ")[1].split(" RETURN")[0].split(" WITH")[0].strip()
        where_part = where_part.replace('"', "'")
        # Chia dòng ngắn lại nếu WHERE quá dài
        chunks = [where_part[i:i+60] for i in range(0, len(where_part), 60)]
        where_part = "<br/>&nbsp;&nbsp;&nbsp;&nbsp;".join(chunks)
        lines.append(f"⚙️ LỌC: {where_part}")
        
    return "<br/>".join(lines)

def build_mermaid(node, parent_id=None, level=1):
    mermaid_lines = []
    
    sev_class = "low"
    if node.get("severity") == "MEDIUM":
        sev_class = "medium"
    elif node.get("severity") == "HIGH":
        sev_class = "high"
    elif node.get("severity") == "CRITICAL":
        sev_class = "critical"
        
    node_id = node.get("id")
    node_name = node.get("name").replace('"', "'")
    
    query = node.get("query", "")
    logic_html = extract_query_logic(query)
    
    if logic_html:
        node_label = f"<b>{node_name}</b><br/><hr/><i>{logic_html}</i>"
    else:
        node_label = f"<b>{node_name}</b>"
    
    # Wrap subgraph label in quotes to avoid mermaid parsing errors
    mermaid_lines.append(f'    subgraph Layer_{node_id} ["Lớp {level}"]')
    mermaid_lines.append(f'        {node_id}["{node_label}"]:::{sev_class}')
    mermaid_lines.append(f'    end')
    
    if parent_id:
        # Đường nối đơn giản, gỡ bỏ chữ trên Edge để đồ thị thoáng hơn
        mermaid_lines.append(f'    {parent_id} ==> {node_id}')
        
    next_nodes = node.get("on_match", {}).get("next", [])
    for n in next_nodes:
        mermaid_lines.extend(build_mermaid(n, node_id, level + 1))
        
    return mermaid_lines

def main():
    parser = argparse.ArgumentParser(description="Tạo sơ đồ Mermaid tự động cho các tập luật JSON")
    parser.add_argument("--folder", "-f", required=True, help="Tên thư mục chứa các file rule JSON (ví dụ: rules hoặc generic_rules)")
    args = parser.parse_args()
    
    folder = args.folder
    files = sorted(glob.glob(os.path.join(folder, '*.json')))
    
    if not files:
        print(f"❌ Không tìm thấy file .json nào trong thư mục: {folder}")
        return
        
    readme_content = f"# Hệ Thống Tập Luật Đa Nguồn ({folder})\n\nDưới đây là lưu đồ tự động tạo cho các tập luật trong thư mục này.\n\n"

    for fpath in files:
        with open(fpath, 'r', encoding='utf-8') as f:
            try:
                data = json.load(f)
            except:
                continue

        if isinstance(data, dict):
            rule_list = [data]
        elif isinstance(data, list):
            rule_list = data
        else:
            continue
            
        for rule_item in rule_list:
            rule_id = rule_item.get("rule_id", "Unknown")
            rule_name = rule_item.get("rule_name", "Unknown")
            
            readme_content += f"## {rule_id}: {rule_name}\n"
            readme_content += f"**File:** `{os.path.basename(fpath)}`\n\n"
            readme_content += "```mermaid\ngraph TD\n"
            readme_content += "    classDef low fill:#fef08a,stroke:#ca8a04,stroke-width:2px,color:#854d0e;\n"
            readme_content += "    classDef medium fill:#f97316,stroke:#c2410c,stroke-width:2px,color:#fff;\n"
            readme_content += "    classDef high fill:#dc2626,stroke:#991b1b,stroke-width:2px,color:#fff;\n"
            readme_content += "    classDef critical fill:#7f1d1d,stroke:#450a0a,stroke-width:2px,color:#fff;\n\n"
            
            tree = rule_item.get("tree", {})
            if tree:
                lines = build_mermaid(tree)
                readme_content += "\n".join(lines) + "\n"
                
            readme_content += "```\n\n"

    readme_path = os.path.join(folder, 'README.md')
    with open(readme_path, 'w', encoding='utf-8') as f:
        f.write(readme_content)
        
    print(f"✅ Đã tạo thành công file {readme_path} cho {len(files)} tập luật!")

if __name__ == "__main__":
    main()

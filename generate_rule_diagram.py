import json
import glob
import os
import re
import argparse
import textwrap

def extract_query_logic(query):
    if not query:
        return ""
    # Format Cypher query nicely for markdown block
    formatted = query.replace(" WHERE ", "\nWHERE ").replace(" RETURN ", "\nRETURN ").replace(" AND ", "\n  AND ")
    return formatted

def extract_queries_markdown(node, level=1):
    md_lines = []
    node_name = node.get("name")
    query = node.get("query", "")
    if query:
        md_lines.append(f"**Lớp {level}: {node_name}**")
        md_lines.append("```cypher")
        md_lines.append(format_cypher(query))
        md_lines.append("```")
        md_lines.append("")
        
    next_nodes = node.get("on_match", {}).get("next", [])
    for n in next_nodes:
        md_lines.extend(extract_queries_markdown(n, level + 1))
        
    return md_lines

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
    
    node_label = f"<b>{node_name}</b>"
    
    # Wrap subgraph label in quotes to avoid mermaid parsing errors
    mermaid_lines.append(f'    subgraph Layer_{node_id} ["Lớp {level}"]')
    mermaid_lines.append(f'        {node_id}["{node_label}"]:::{sev_class}')
    mermaid_lines.append(f'    end')
    
    if parent_id:
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
                
                readme_content += "#### Chi tiết câu lệnh Cypher (Logic Detection)\n"
                query_lines = extract_queries_markdown(tree)
                readme_content += "\n".join(query_lines) + "\n"

    readme_path = os.path.join(folder, 'README.md')
    with open(readme_path, 'w', encoding='utf-8') as f:
        f.write(readme_content)
        
    print(f"✅ Đã tạo thành công file {readme_path} cho {len(files)} tập luật!")

if __name__ == "__main__":
    main()

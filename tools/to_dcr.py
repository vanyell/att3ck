import os
import json
import argparse
from pathlib import Path

def convert_to_dcr_format(input_path: str, output_path: str = None):
    """
    Converts newline-delimited JSON logs into a JSON array for Azure Log Analytics DCR ingestion.
    """
    input_file = Path(input_path)
    if not input_file.exists():
        print(f"Error: File {input_path} not found.")
        return

    objects = []
    with open(input_file, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    objects.append(json.loads(line))
                except json.JSONDecodeError as e:
                    print(f"Warning: Skipping invalid JSON line in {input_path}: {e}")

    if not output_path:
        # Default to overwriting or appending _dcr.json
        output_path = str(input_file.with_name(f"{input_file.stem}_dcr.json"))

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(objects, f, indent=2, ensure_ascii=False)
    
    print(f"Successfully converted {len(objects)} events to {output_path}")

def main():
    parser = argparse.ArgumentParser(description="Convert Kinetix newline-delimited JSON logs to Azure DCR-compatible JSON arrays.")
    parser.add_argument("path", help="Path to a single .json file or a directory of .json files.")
    parser.add_argument("--output-dir", help="Optional output directory. If not specified, uses the same directory as input.")
    
    args = parser.parse_args()
    
    target = Path(args.path)
    if target.is_dir():
        for json_file in target.glob("*.json"):
            # Skip already converted files to avoid recursion
            if json_file.name.endswith("_dcr.json") or json_file.name == "Kinetix_Unified.json":
                continue
                
            out_path = None
            if args.output_dir:
                os.makedirs(args.output_dir, exist_ok=True)
                out_path = os.path.join(args.output_dir, f"{json_file.stem}_dcr.json")
                
            convert_to_dcr_format(str(json_file), out_path)
    else:
        convert_to_dcr_format(args.path)

if __name__ == "__main__":
    main()

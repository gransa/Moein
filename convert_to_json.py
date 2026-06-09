import json
import datetime
import os

def generate_config():
    input_file = 'Configs.txt'
    output_file = 'NG-JSON-Configs.txt'

    # 1. Read input
    with open(input_file, 'r', encoding='utf-8') as f:
        lines = [line.strip() for line in f if line.strip()]

    # 2. Logic to ensure output is always unique
    # Adding a timestamp forces a change, ensuring git always detects it
    data = {
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "configs": lines
    }

    # 3. Write output
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(data, f, indent=4)
        
    print(f"Successfully generated {output_file}")

if __name__ == "__main__":
    generate_config()

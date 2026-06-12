name: Generate JSON Client Configs

on:
  schedule:
    - cron: '23 * * * *'
  push:
    paths:
      - 'Configs.txt'
  workflow_dispatch:

jobs:
  build-json:
    runs-on: ubuntu-latest
    permissions:
      contents: write

    steps:
      - name: Checkout Repository
        uses: uses: actions/checkout@v4.2.2
        with:
          fetch-depth: 0

      - name: Set up Python
        uses: actions/setup-python@v5.3.0
        with:
          python-version: '3.11'

      - name: Compile Profile Array Layouts
        run: |
          # Remove old output to ensure a fresh generation
          rm -f NG-JSON-Configs.txt
          
          # Run your conversion script
          python convert_to_json.py
          
          # Safety check
          if [ ! -s NG-JSON-Configs.txt ]; then
            echo "::error::Output file NG-JSON-Configs.txt is empty."
            exit 1
          fi

      - name: Commit and Push
        run: |
          git config user.name "JSON Compiler Engine"
          git config user.email "action@github.com"
          
          # Force a small timestamp file update so Git ALWAYS detects a change 
          # even if the scrambled JSON output mirrors previous layouts
          date -u +"%Y-%m-%d %H:%M:%S UTC" > last_build.txt
          
          git add NG-JSON-Configs.txt last_build.txt
          
          # Get current timestamp for the commit message
          TIMESTAMP=$(date -u +"%Y-%m-%d %H:%M:%S UTC")
          
          # --allow-empty forces GitHub to push a new commit ID to main every hour.
          # This breaks upstream CDN caches so your subscription links update properly.
          git commit --allow-empty -m "Auto Sync: $TIMESTAMP"
          
          git push

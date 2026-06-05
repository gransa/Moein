name: Daily Fingerprint Updater

on:
  schedule:
    - cron: '0 3 * * *'
  workflow_dispatch:

permissions:
  contents: write

env:
  FORCE_JAVASCRIPT_ACTIONS_TO_NODE24: "true"

jobs:
  update:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout repository
        uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install requests

      - name: Update Certificate Fingerprints
        run: python update_fingerprints.py

      - name: Commit and Push changes
        run: |
          git config user.name "Fingerprint Updater"
          git config user.email "action@github.com"
          git add Configs.txt
          if git diff --staged --quiet; then
            echo "No changes to commit"
          else
            git commit -m "Update fingerprints - $(date '+%Y-%m-%d %H:%M:%S')"
            git push
          fi

import sublime
import json
import os

os.environ["PYTHONIOENCODING"] = "utf-8"

sublime_client = sublime.Sublime()

rules, queries = sublime.util.load_yml_path("sublime-rules/detection-rules/")
raw_message = sublime.util.load_eml("sublime-rules/emls/reported_phish.eml")

print(f"[Sublime Python SDK] Analyzing message against {len(rules)} detection rules...")
response = sublime_client.analyze_message(raw_message, rules, queries)

rule_results = response.get("rule_results", [])
flagged_rules = [r for r in rule_results if r.get("flagged")]

print(f"\n--- ANALYSIS SUMMARY ---")
print(f"Total Rules Evaluated: {len(rule_results)}")
print(f"Flagged Rules Count: {len(flagged_rules)}")

for item in flagged_rules:
    rule_name = item.get("rule", {}).get("name") or item.get("name")
    print(f"🛑 FLAGGED: {rule_name}")

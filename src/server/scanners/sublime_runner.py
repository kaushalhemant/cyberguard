import sys
import json
import os
import sublime

os.environ["PYTHONIOENCODING"] = "utf-8"

def main():
    if len(sys.argv) < 3:
        print(json.dumps({"error": "Usage: sublime_runner.py <eml_path> <rules_dir>"}))
        sys.exit(1)

    eml_path = sys.argv[1]
    rules_dir = sys.argv[2]

    if not os.path.exists(eml_path) or not os.path.exists(rules_dir):
        print(json.dumps({"totalRulesEvaluated": 0, "flaggedCount": 0, "flaggedRules": []}))
        sys.exit(0)

    try:
        sublime_client = sublime.Sublime()
        rules, queries = sublime.util.load_yml_path(rules_dir)
        raw_message = sublime.util.load_eml(eml_path)

        response = sublime_client.analyze_message(raw_message, rules, queries)

        rule_results = response.get("rule_results", [])
        flagged_rules = []

        for item in rule_results:
            if item.get("matched") is True:
                rule_info = item.get("rule") or {}
                flagged_rules.append({
                    "name": rule_info.get("name") or item.get("name") or "Unnamed Threat Rule",
                    "severity": rule_info.get("severity") or "medium",
                    "source": rule_info.get("source")
                })

        result = {
            "totalRulesEvaluated": len(rule_results),
            "flaggedCount": len(flagged_rules),
            "flaggedRules": flagged_rules
        }

        print(json.dumps(result))
    except Exception as e:
        print(json.dumps({"error": str(e), "totalRulesEvaluated": 0, "flaggedCount": 0, "flaggedRules": []}))

if __name__ == "__main__":
    main()

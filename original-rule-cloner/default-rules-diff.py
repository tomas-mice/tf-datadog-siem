from operator import eq
import sys
import os
from functions import *

DD_API_KEY = os.environ["DD_API_KEY"]
DD_APP_KEY = os.environ["DD_APP_KEY"]
DD_RULE_TYPES = [
    "cloud_configuration",
    "infrastructure_configuration",
    "log_detection",
    "workload_security",
]

detection_rules = get_detection_rules_from_datadog(DD_API_KEY, DD_APP_KEY)
removed_rules_ids = []
for rule_type in DD_RULE_TYPES:
    print(f"Managing rules of type '{rule_type}'")
    imported_rules = get_imported_rules(rule_type)
    removed_rules = get_removed_rules(detection_rules, rule_type)
    for rule in removed_rules:
        rule_id = list(rule["datadog_security_monitoring_default_rule"].keys())[
            0
        ].split("_")[-1]

        removed_rules_ids.append(rule_id)
        remove_resource_from_file(rule_type, rule_id)
        remove_resource_from_outputs_file(rule_id)


# new_rules = get_new_rules_ids("cloud_configuration")

print(",".join(removed_rules_ids))
if removed_rules_ids.__len__().__eq__(0):
    print("NOT_FOUND")

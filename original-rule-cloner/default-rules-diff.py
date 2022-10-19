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

for rule_type in DD_RULE_TYPES:
    print(f"Managing rules of tyle '{rule_type}'")
    imported_rules = get_imported_rules(rule_type)
    removed_rules = get_removed_rules(detection_rules, rule_type)

# remove_resource_from_file(type, resource_id)
# new_rules = get_new_rules_ids("cloud_configuration")

print("FINISH")

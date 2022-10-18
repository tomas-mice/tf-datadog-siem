import requests
import os
import hcl2

DD_API_KEY = os.environ["DD_API_KEY"]
DD_APP_KEY = os.environ["DD_APP_KEY"]
DD_RULE_TYPES = [
    "cloud_configuration",
    "infrastructure_configuration",
    "log_detection",
    "workload_security",
]

try:
    print("Getting detection rules from Datadog.")
    detection_rules_response = requests.get(
        "https://api.datadoghq.com/api/v2/security_monitoring/rules?page%5Bsize%5D=2000",
        headers={"DD-API-KEY": DD_API_KEY, "DD-APPLICATION-KEY": DD_APP_KEY},
    )
except Exception as e:
    exit(f"Failed getting detection rules with error: {e}.")


if detection_rules_response.status_code != 200:
    print(
        f"Failed to get the detection rule list from Datadog {detection_rules_response.status_code}"
    )
    os.exit(1)

detection_rules = detection_rules_response.json()["data"]

dry_run = True


def rule_already_in_tf(imported_rules, rule_id):
    if (
        [
            rule
            for rule in imported_rules
            if list(rule["datadog_security_monitoring_default_rule"].keys())[0].split(
                "_"
            )[-1]
            == rule_id
        ]
        .__len__()
        .__gt__(0)
    ):
        return True


def rule_is_in_datadog(detection_rules, rule_id):
    if [rule for rule in detection_rules if rule["id"] == rule_id].__len__().__gt__(0):
        return True


def get_imported_rules(type):
    print(f"Getting imported rules of type '{type}' from file")
    with open(f"./default-rules/{type}.tf", "r") as file:
        rules = hcl2.load(file)

    return rules["resource"]


def get_new_rules_ids(type):
    print("Getting rule IDs that are not imported to TF files.")
    imported_default_rules = get_imported_rules(type)

    not_imported_rules = []

    for rule in detection_rules:
        if rule["type"] not in [
            "cloud_configuration"
        ]:  # , "infrastructure_configuration"
            continue
        if rule_already_in_tf(imported_default_rules, rule["id"]):
            continue
        not_imported_rules.append(rule["id"])

    print(not_imported_rules)
    return not_imported_rules


def get_removed_rules(type):
    print("Getting rules removed from Datadog but still present in TF files.")
    imported_default_rules = get_imported_rules(type)

    not_existing_rules = []
    for rule in imported_default_rules:
        if not rule_is_in_datadog(
            detection_rules,
            list(rule["datadog_security_monitoring_default_rule"].keys())[0].split("_")[
                -1
            ],
        ):
            not_existing_rules.append(rule)

    print(f"RUles found: {not_existing_rules}")
    return not_existing_rules


type = "test"
resource_id = "zlj-jxo-10f"


def remove_resource_from_file(type, resource_id):
    lines_to_remove = 8
    found = False
    with open(f"./default-rules/{type}.tf", "r") as f:
        lines = f.readlines()
    with open(f"./default-rules/{type}.tf", "w") as f:
        for line in lines:
            if line.__contains__(resource_id):
                found = True
            if found and lines_to_remove > 0:
                lines_to_remove -= 1
                continue
            f.write(line)


# remove_resource_from_file(type, resource_id)
# new_rules = get_new_rules_ids("cloud_configuration")
removed_rules = get_removed_rules("cloud_configuration")

print("FINISH")

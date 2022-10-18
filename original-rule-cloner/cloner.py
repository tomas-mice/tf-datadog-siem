import requests
import os
import hcl2

file_dir = os.path.dirname(os.path.realpath('__file__'))
print(file_dir)

with open('./default-rules/cloud_configuration.tf', 'r') as file:
    dict = hcl2.load(file)
    
list(dict['resource'][0]['datadog_security_monitoring_default_rule'].keys())[0]

DD_API_KEY = os.environ["DD_API_KEY"]
DD_APP_KEY = os.environ["DD_APP_KEY"]
detection_rules_response = requests.get(
    "https://api.datadoghq.com/api/v2/security_monitoring/rules?page%5Bsize%5D=2000",
    headers={"DD-API-KEY": DD_API_KEY, "DD-APPLICATION-KEY": DD_APP_KEY},
)

dry_run = True

if detection_rules_response.status_code != 200:
    print(
        f"Failed to get the detection rule list {detection_rules_response.status_code}"
    )
    os.exit(1)

detection_rules = detection_rules_response.json()["data"]


def is_rule_already_cloned(detection_rules, rule_name):
    for detection_rule in detection_rules:
        if not detection_rule["name"].startswith("[TBOL] "):
            continue
        if detection_rule["name"] == f"[TBOL] {rule_name}":
            # if dry_run:
            # print(f"{rule_name: <80} rule is already cloned")
            return True
    return False


not_cloned_detection_rules = []

for detection_rule in detection_rules:
    if detection_rule["type"] not in {"workload_security", "log_detection"}: # CHANGED FROM not int
        continue
    if detection_rule["creationAuthorId"] != 0:  # not a datadog embedded detection rule
        continue
    if detection_rule["name"].startswith(
        "[TBOL] "
    ):  # should never get to this, but just in case
        continue
    if is_rule_already_cloned(detection_rules, detection_rule["name"]):
        continue

    print(f"{detection_rule['name']} | {detection_rule['type']}")
    not_cloned_detection_rules.append(detection_rule)

    original_rule_name = detection_rule["name"]
    detection_rule["name"] = f"[TBOL] {detection_rule['name']}"
    detection_rule["isEnabled"] = False

    if "id" in detection_rule:
        del detection_rule["id"]
    if "createdAt" in detection_rule:
        del detection_rule["createdAt"]
    if "updateAuthorId" in detection_rule:
        del detection_rule["updateAuthorId"]
    if "creationAuthorId" in detection_rule:
        del detection_rule["creationAuthorId"]

    if dry_run:
        # print(f"Cloned {original_rule_name} => {detection_rule['name']} ")
        continue

    # clone_response = requests.post(
    #     "https://api.datadoghq.com/api/v2/security_monitoring/rules",
    #     headers={"DD-API-KEY": DD_API_KEY, "DD-APPLICATION-KEY": DD_APP_KEY},
    #     json=detection_rule,
    # )
    # if clone_response.status_code == 200:
    #     print(f"{original_rule_name} => {detection_rule['name']} ")
    #     continue

    print(
        f"Failed to clone {original_rule_name} StatusCode: {clone_response.status_code} Error: {clone_response.content}"
    )

not_cloned_detection_rules

print("The end")

# tf-datadog-siem
TF homeland for Datadog SIEM detection rules

# Possilbe issues

**Default rule removed from datadog**

Ocasionally it might happen that Datadog removes default rules. In that situation during actions run error occurs

```log
Error: 404 Not Found

with module.default-detection-rules.datadog_security_monitoring_default_rule.tfer--security_monitoring_default_rule_5bp-tcn-yvr,
on default-rules/cloud_configuration.tf line 97, in resource "datadog_security_monitoring_default_rule" "tfer--security_monitoring_default_rule_5bp-tcn-yvr":
97: resource "datadog_security_monitoring_default_rule" "tfer--security_monitoring_default_rule_5bp-tcn-yvr" {
```

To solve this resource needs to be removed from Terraform state (example below) and .tf files

```hcl
terraform state rm module.default-detection-rules.datadog_security_monitoring_default_rule.tfer--security_monitoring_default_rule_5bp-tcn-yvr
```

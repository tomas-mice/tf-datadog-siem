resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_lzi-yqb-k8e" {
  case {
    condition = "critical_severity_vulnerability > 0"
    name      = "Critical Severity Vulnerabiluty"
    status    = "critical"
  }

  case {
    condition = "high_severity_vulnerability > 0"
    name      = "High Severity Vulnerabiluty"
    status    = "high"
  }

  case {
    condition = "medium_severity_vulnerability > 0"
    name      = "Medium Severity Vulnerabiluty"
    status    = "medium"
  }

  case {
    condition = "low_severity_vulnerability > 0"
    name      = "Low Severity Vulnerabiluty"
    status    = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect vulnerabilities in container images.\n\n## Strategy\nThis rule lets you monitor Twistlock logs `(@vulnerability.log_type:vulnerability)` to detect vulnerabilities in a container image. \n\n## Triage and response\n1. Determine the impact of this vulnerability.\n2. Update the container image in the registry with a patched version of the software.\n3. Deploy the new image to all containers running the vulnerable image.\n\n## Change Log\n29 Jun 2022 - Added queries for various vulnerability severity levels."
  name               = "[TBOL] Container image vulnerability detected"

  options {
    decrease_criticality_based_on_env = "true"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["container_name"]
    name            = "critical_severity_vulnerability"
    query           = "source:twistlock @vulnerability.log_type:vulnerability @vulnerability.severity:critical"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["container_name"]
    name            = "high_severity_vulnerability"
    query           = "source:twistlock @vulnerability.log_type:vulnerability @vulnerability.severity:high"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["container_name"]
    name            = "medium_severity_vulnerability"
    query           = "source:twistlock @vulnerability.log_type:vulnerability @vulnerability.severity:medium"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["container_name"]
    name            = "low_severity_vulnerability"
    query           = "source:twistlock @vulnerability.log_type:vulnerability @vulnerability.severity:low"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_jlw-i0n-rpe" {
  case {
    condition = "critical_severity_vulnerability > 0"
    name      = "Critical Severity Vulnerability"
    status    = "critical"
  }

  case {
    condition = "high_severity_vulnerability > 0"
    name      = "High Severity Vulnerability"
    status    = "high"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a container is not running within compliance standards.\n\n## Strategy\nThis rule lets you monitor Twistlock logs to detect when a `High` or `Critical` severity compliance issue is discovered in a running container. \n\n## Triage and response\n1. Determine the impact of the compliance finding.\n2. Remediate the compliance finding.\n\n## Change Log\n27 Jun 2022 - Updated Rule and added findings for critical vulnerabilities."
  name               = "[TBOL] Container violated compliance standards"

  options {
    decrease_criticality_based_on_env = "true"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["container_name"]
    name            = "critical_severity_vulnerability"
    query           = "source:twistlock @vulnerability.log_type:compliance @vulnerability.severity:critical"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["container_name"]
    name            = "high_severity_vulnerability"
    query           = "source:twistlock @vulnerability.log_type:compliance @vulnerability.severity:high"
  }

  type = "log_detection"
}

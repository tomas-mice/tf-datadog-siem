resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_xb5-g7t-tta" {
  case {
    condition = "a > 0"
    status    = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an IP is flagged by Signal Sciences.\n\n## Strategy\nThis rule lets you monitor Signal Sciences events submitted through the Signal Sciences [integration][1] to detect when an IP is flagged. \n\n## Triage and response\n1. Determine whether the attack is a false positive.\n2. Determine whether the attack was successful.\n3. If the attack exploited a vulnerability in the application, triage the vulnerability.\n\n[1]: https://app.datadoghq.com/account/settings#integrations/sigsci\n"
  name               = "[TBOL] Signal Sciences flagged an IP"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "300"
    max_signal_duration               = "300"
  }

  query {
    aggregation = "count"
    query       = "source:signal_sciences @title:*flag"
  }

  type = "log_detection"
}

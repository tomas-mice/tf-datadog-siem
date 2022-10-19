resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_e5u-ocz-41j" {
  case {
    status = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetects when a specific AWS Web Application Firewall (WAF) rule blocks an anomalous amount of traffic.\n\n## Strategy\nThe rule monitors AWS WAF logs and detects when the `@system.action` has a value of `BLOCK`.\n\n## Triage and response\n1. Inspect the `@webaclId`: `{{@webaclId}}` logs to confirm if the observed traffic should have been blocked or not.\n2. If the request should have been blocked, then navigate to the IP Investigation dashboard. Inspect other requests from the IP address:{{@network.client.ip}} to find any other potentially malicious behaviors from the IP."
  name               = "[TBOL] AWS WAF traffic blocked by specific rule"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "anomaly_detection"
    evaluation_window                 = "1800"
    keep_alive                        = "1800"
    max_signal_duration               = "1800"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@webaclId"]
    name            = "waf_traffic_block"
    query           = "service:waf @system.action:BLOCK"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_dvb-8n2-bho" {
  case {
    status = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a specific AWS Web Application Firewall (WAF) rule blocks traffic from multiple IPs.\n\n## Strategy\nThe rule monitors AWS WAF logs and detects when the `@system.action` has a value of `BLOCK`.\n\n## Triage and response\n1. Inspect the `@http.request_id`: `{{@http.request_id}}` to confirm if this request should have been blocked or not.\n2. If the request should have been blocked, then navigate to the IP Investigation dashboard. Inspect other requests from the IP address:{{@network.client.ip}} to find any other potentially malicious behaviors from the IP.\n"
  name               = "[TBOL] AWS WAF traffic blocked by specific rule on multiple IPs"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "anomaly_detection"
    evaluation_window                 = "1800"
    keep_alive                        = "1800"
    max_signal_duration               = "1800"
  }

  query {
    aggregation     = "cardinality"
    distinct_fields = ["@network.client.ip"]
    group_by_fields = ["@webaclId"]
    name            = "waf_traffic_block"
    query           = "service:waf @system.action:BLOCK"
  }

  type = "log_detection"
}

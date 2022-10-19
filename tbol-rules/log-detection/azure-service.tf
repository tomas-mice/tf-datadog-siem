resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_6mi-c6f-xy5" {
  case {
    condition = "container_exec_success > 0"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a command is executed on a container instance with the Azure API.\n\n## Strategy\nMonitor Azure container instance logs where `@evt.name` is `\"MICROSOFT.CONTAINERINSTANCE/CONTAINERGROUPS/CONTAINERS/EXEC/ACTION\"` and `@evt.outcome` is `Success`.\n\n## Triage and response\n1. Verify that the user (`{{@usr.id}}`) should be executing commands on the container (`@resourceId`).\n2. If the activity is not expected, investigate the activity around the container (`@resourceId`).\n"
  name               = "[TBOL] Azure user ran command on container instance"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation = "count"
    name        = "container_exec_success"
    query       = "service:azure @evt.name:\"MICROSOFT.CONTAINERINSTANCE/CONTAINERGROUPS/CONTAINERS/EXEC/ACTION\" @evt.outcome:Success"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_h30-vrk-ohf" {
  case {
    condition = "a > 0"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a diagnostic setting is deleted which can disable centralized logging and metrics on Azure.\n\n## Strategy\nMonitor Azure logs where `@evt.name` is `\"MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE\"` and `@evt.outcome` is `Success`.\n\n## Triage and response\n1. Inspect the diagnostic setting resource which is found in `@resourceId`.\n2. Verify that the user (`{{@usr.id}}`) to determine if the removal of the resource is legitimate."
  name               = "[TBOL] Azure diagnostic setting deleted or disabled"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@usr.id"]
    query           = "service:azure @evt.name:\"MICROSOFT.INSIGHTS/DIAGNOSTICSETTINGS/DELETE\" @evt.outcome:Success"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_xmc-rvg-hln" {
  case {
    condition = "standardized_attributes > 0"
    name      = "standardized"
    status    = "high"
  }

  case {
    condition = "non_standardized_attributes > 0"
    name      = "non-standardized"
    status    = "high"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when the Domain Administrator group is modified.\n\n## Strategy\nMonitoring of Windows event logs where `@evt.id` is 4737 and the `@Event.EventData.Data.TargetUserName:\"Domain Admins\"`\n\n## Triage \u0026 Response\nVerify if `{{@Event.EventData.Data.SubjectUserName}}` has a legitimate reason for changing the `Domain Admins` group\n"
  name               = "[TBOL] Windows Domain Admin Group Changed"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@Event.EventData.Data.SubjectUserName"]
    name            = "standardized_attributes"
    query           = "source:windows.events @evt.id:4737 @Event.EventData.Data.TargetUserName:\"Domain Admins\""
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@Event.EventData.Data.SubjectUserName"]
    name            = "non_standardized_attributes"
    query           = "@Event.System.EventID:4737 @Event.EventData.Data.TargetUserName:\"Domain Admins\""
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_1px-6ut-vc8" {
  case {
    condition = "standardized_attributes > 0"
    name      = "standardized"
    status    = "high"
  }

  case {
    condition = "non_standardized_attributes > 0"
    name      = "non-standardized"
    status    = "high"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a user clears Windows Security logs.\n\n## Strategy\nMonitoring of Windows event logs where `@evt.id` is `1102`.\n\n## Triage and response\nVerify if `{{@Event.UserData.LogFileCleared.SubjectUserName}}` has a legitimate reason to clear the security event logs on `{{host}}`. \n"
  name               = "[TBOL] Windows Audit Log Cleared"

  options {
    decrease_criticality_based_on_env = "true"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@Event.UserData.LogFileCleared.SubjectUserName"]
    name            = "standardized_attributes"
    query           = "source:windows.events @evt.id:1102"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@Event.UserData.LogFileCleared.SubjectUserName"]
    name            = "non_standardized_attributes"
    query           = "@Event.System.EventID:1102"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_hcd-bry-ckm" {
  case {
    condition = "standardized_attributes > 0"
    name      = "standardized"
    status    = "info"
  }

  case {
    condition = "non_standardized_attributes > 0"
    name      = "non-standardized"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a user is added to the Domain Administrator group. A rogue active directory account can added to the Domain Admins group.\n\n## Strategy\nMonitoring of Windows event logs where `@evt.id` is `4728` and the `@Event.EventData.Data.TargetUserName:\"Domain Admins\"`\n\n## Triage \u0026 Response\nVerify if `{{@Event.EventData.Data.TargetUserName}}` should be added to the `Domain Admins` group\n"
  name               = "[TBOL] Windows User Added to Domain Admin Group"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@Event.EventData.Data.SubjectUserName", "@Event.EventData.Data.TargetUserName"]
    name            = "standardized_attributes"
    query           = "source:windows.events @evt.id:4728 @Event.EventData.Data.TargetUserName:\"Domain Admins\""
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@Event.EventData.Data.SubjectUserName", "@Event.EventData.Data.TargetUserName"]
    name            = "non_standardized_attributes"
    query           = "@Event.System.EventID:4728 @Event.EventData.Data.TargetUserName:\"Domain Admins\""
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_pxb-qwk-j9f" {
  case {
    condition = "standardized > 0"
    name      = "standardized"
    status    = "high"
  }

  case {
    condition = "non_standardized > 0"
    name      = "non-standardized"
    status    = "high"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a user resets the Directory Services Restore Mode (DSRM). The DSRM enabled emergency access to a Domain Controller. The DSRM user is a local administrator account that can be utilized for persistence. \n\n## Strategy\nMonitoring of Windows event logs where `@evt.id` is `4794`.\n\n## Triage and response\nVerify if `{{@Event.UserData.LogFileCleared.SubjectUserName}}` has a legitimate reason to change the DSRM password on `{{host}}`. "
  name               = "[TBOL] Windows Directory Service Restore Mode password changed"

  options {
    decrease_criticality_based_on_env = "true"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["host"]
    name            = "standardized"
    query           = "source:windows.events @evt.id:4794"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["host"]
    name            = "non_standardized"
    query           = "@Event.System.EventID:4794"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_rkz-wfj-meh" {
  case {
    condition = "standardized_attributes > 0"
    name      = "standardized"
    status    = "medium"
  }

  case {
    condition = "non_standardized_attributes > 0"
    name      = "non-standardized"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when the Windows firewall is disabled.\n\n## Strategy\nMonitor the Windows event logs where `@evt.id` is `4950` and the `@Event.EventData.Data.SettingValue:No`.\n\n## Triage and response\nVerify if `{{@Event.System.Computer}}` has a legitimate reason for having the Windows firewall disabled."
  name               = "[TBOL] Windows Firewall Disabled"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@Event.System.Computer"]
    name            = "standardized_attributes"
    query           = "source:windows.events @evt.id:4950 @Event.EventData.Data.SettingValue:No"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@Event.System.Computer"]
    name            = "non_standardized_attributes"
    query           = "@Event.System.EventID:4950 @Event.EventData.Data.SettingValue:No"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_s2y-5g4-4ap" {
  case {
    condition = "standardized_attributes > 0"
    name      = "standardized"
    status    = "low"
  }

  case {
    condition = "non_standardized_attributes > 0"
    name      = "non-standardized"
    status    = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a user runs the `net` command to enumerate the `Administrators` group, which could be indicative of adversarial reconnaissance activity.\n\n## Strategy\nMonitoring of Windows event logs where `@evt.id` is `4799`, `@Event.EventData.Data.CallerProcessName` is `*net1.exe` and `@Event.EventData.Data.TargetUserName` is `Administrators`.\n\n## Triage and response\nVerify if `{{@Event.EventData.Data.SubjectUserName}}` has a legitimate reason to check for users in the Administrator group on `{{host}}`. \n"
  name               = "[TBOL] Windows Net command executed to enumerate administrators"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@Event.System.Computer"]
    name            = "standardized_attributes"
    query           = "source:windows.events @evt.id:4799 @Event.EventData.Data.CallerProcessName:*net1.exe @Event.EventData.Data.TargetUserName:Administrators"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@Event.System.Computer"]
    name            = "non_standardized_attributes"
    query           = "@Event.System.EventID:4799 @Event.EventData.Data.CallerProcessName:*net1.exe @Event.EventData.Data.TargetUserName:Administrators"
  }

  type = "log_detection"
}

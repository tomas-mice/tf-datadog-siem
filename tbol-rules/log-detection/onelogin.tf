resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_xba-jnu-4yy" {
  case {
    condition = "admin_assumed_user > 0"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a OneLogin user with appropriate privileges assumes another OneLogin user's identity. Logging in as another user allows the user to view another OneLogin user's account and perform actions on their behalf. \n\n## Strategy\nThis rule lets you monitor the following OneLogin events to detect when an administrator assumes another OneLogin user's identity:\n\n* `@evt.name:USER_ASSUMED_USER`\n\n## Triage and response\n1. Determine whether the user (`{{@usr.name}}`) should be legitimately assuming another user's identity.\n2. If the activity was not legitimate, review all activity from `{{@usr.name}}` and the IP (`{{@network.client.ip}}`) associated with this signal. \n"
  name               = "[TBOL] OneLogin administrator assumed a user"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@usr.name"]
    name            = "admin_assumed_user"
    query           = "source:onelogin @evt.name:USER_ASSUMED_USER"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_jih-kcf-iwg" {
  case {
    condition = "user_granted_admin_privileges > 0"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a OneLogin administrator grants additional privileges to another OneLogin user.\n\n## Strategy\nThis rule lets you monitor the following OneLogin events to detect when an administrator grants additional privileges to another OneLogin user:\n\n* `@evt.name:PRIVILEGE_GRANTED_TO_USER`\n\n## Triage and response\n1. Determine whether the user (`{{@actor_user_name}}`) should be legitimately adding additional roles to `@usr.name`. **Note:** The role granted to the user is not available in OneLogin logs.\n2. If the activity was not legitimate, review all activity from `{{@actor_user_name}}` and the IP (`{{@network.client.ip}}`) associated with this signal. "
  name               = "[TBOL] OneLogin user granted administrative privileges"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@usr.name"]
    name            = "user_granted_admin_privileges"
    query           = "source:onelogin @evt.name:PRIVILEGE_GRANTED_TO_USER"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_jk7-b8o-0hw" {
  case {
    condition = "user_locked_out > 0"
    status    = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a OneLogin user is locked out. This may be common if the user is repeatedly failing to log in. This rule is most useful when correlated with other anomalous activity for the user.\n\n## Strategy\nThis rule lets you monitor the following OneLogin events to when a user is locked out:\n* `@evt.name:USER_LOCKED`\n\n## Triage and response\n1. Determine whether the user (`{{@usr.name}}`) was legitimately trying to authenticate and was locked out.\n2. If the activity was not legitimate, review all activity from the IP (`{{@network.client.ip}}`) associated with this signal. "
  name               = "[TBOL] OneLogin user locked out"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@usr.name"]
    name            = "user_locked_out"
    query           = "source:onelogin @evt.name:USER_LOCKED"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_qyo-dtx-h1t" {
  case {
    condition = "viewed_secure_note > 0"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a OneLogin user views a secure note.\n\n## Strategy\nThis rule lets you monitor the following OneLogin events to detect when a user views a secure note:\n\n* `@evt.name:PRIVILEGE_GRANTED_TO_USER`\n\nThis rule is useful when correlating its findings with other anomalous events from the same OneLogin user (`{{@actor_user_name}}`).\n\n## Triage and response\n1. Determine whether the OneLogin user (`{{@actor_user_name}}`) should be legitimately accessing secure notes.\n2. If the activity was not legitimate, review all activity from `{{@actor_user_name}}` and the IP (`{{@network.client.ip}}`) associated with this signal. "
  name               = "[TBOL] OneLogin user viewed secure note"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@actor_user_name"]
    name            = "viewed_secure_note"
    query           = "source:onelogin @evt.name:USER_VIEWED_NOTE"
  }

  type = "log_detection"
}

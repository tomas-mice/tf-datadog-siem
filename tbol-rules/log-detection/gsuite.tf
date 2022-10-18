resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_fyr-utr-tpk" {
  case {
    condition = "a > 0"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a user attempts to log in with a password which is known to be compromised.\n\n## Strategy\nThis rule allows you to monitor this Google Activity API call to detect if an attacker is trying to login with a leaked password: \n\n* [Leaked password][1]\n\n## Triage and response\n1. Determine which user in your organization owns the compromised password.\n2. Contact the user and ensure they rotate the password on Google and any other accounts where they may have reused this password. Ensure the user is aware of strong password guidelines.\n\n[1]: https://developers.google.com/admin-sdk/reports/v1/appendix/activity/login#account_disabled_password_leak\n"
  name               = "[TBOL] User attempted login with leaked password"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@actor.email"]
    query           = "source:gsuite @evt.category:account_warning @evt.name:account_disabled_password_leak"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_g4r-m2y-rfi" {
  case {
    condition = "workspace_accessed_by_google > 0"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nCreate a signal when Google accesses your Google Workspace tenant using administrative tools. \n\n## Strategy\nMonitor Google Workspace logs to detect `ACCESS` events, which are part of Google's [Access Transparency][1] logs.\n\n## Triage and response\n1. Determine the scope of Google's access activity, which can be found in the `ACCESS` event in the Google Workspace event log.\n2. Review which Google Workspace user (`@event.parameters.OWNER_EMAIL`) and resources (`@event.parameters.RESOURCE_NAME`) were accessed by Google.\n3. Investigate the resource(s) being accessed to determine if there is a legitimate reason it should be reviewed by Google.\n\n[1]: https://support.google.com/a/answer/9230474?hl=en"
  name               = "[TBOL] Google Workspace accessed by Google"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation = "count"
    name        = "workspace_accessed_by_google"
    query       = "source:gsuite service:access_transparency"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_gne-bnz-ez9" {
  case {
    condition = "non_workspace_domain > 0"
    status    = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nCreate a signal when Google Workspace detects a user setting up mail forwarding to a non-Google Workspace domain.\n\n## Strategy\nMonitor Google Workspace logs to detect when `email_forwarding_out_of_domain` events.\n\n## Triage and response\n1. Determine if the email address defined in `@event.parameters.email_forwarding_destination_address` is legitimate.\n2. If the forwarding destination address is not legitimate, review all activity for `{{@usr.email}}` and all activity around the following IP: `{{@network.client.ip}}`."
  name               = "[TBOL] Google Workspace user forwarding email out of non Google Workspace domain"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@usr.email"]
    name            = "non_workspace_domain"
    query           = "source:gsuite @evt.name:email_forwarding_out_of_domain"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_vku-pnx-zy3" {
  case {
    condition = "admin_role_created > 0"
    status    = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nCreate a signal when Google Workspace detects a new Google Workspace administrative role.\n\n## Strategy\nMonitor Google Workspace logs to detect `CREATE_ROLE` events.\n\n## Triage and response\n1. Determine if there is a legitimate reason for the new administrator role (`@event.parameters.ROLE_NAME`).\n2. If there is not a legitimate reason, investigate activity from around the Google Workspace administrator (`{{@usr.email}}`) and IP that created the role (`{{@network.client.ip}}`). "
  name               = "[TBOL] Google Workspace admin role created"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@usr.email"]
    name            = "admin_role_created"
    query           = "source:gsuite @evt.name:CREATE_ROLE"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_7v0-pgb-8tx" {
  case {
    condition = "admin_role_added > 0"
    status    = "high"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a user is added to the super administrator group on Google Workspace.\n\n## Strategy\nMonitor Google Workspace logs to detect `ASSIGN_ROLE` events where `@event.parameters.ROLE_NAME` is `_SEED_ADMIN_ROLE`. \n\n## Triage and response\n1. Verify with the Google admin (`{{@usr.email}}`) if the Google Workspace user in the `@event.parameters.USER_EMAIL` attribute should legitimately be given the super admin role.\n2. If the user in `@event.parameters.USER_EMAIL` was not legitimately added, investigate activity from the IP address (`{{@network.client.ip}}`) that made the role addition.\n3. Review activity around the Google Workspace admin who made the change (`{{@usr.email}}`) and the newly added super admin (`@event.parameters.USER_EMAIL`)."
  name               = "[TBOL] Google Workspace user assigned to super admin role"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@usr.email"]
    name            = "admin_role_added"
    query           = "source:gsuite @evt.name:ASSIGN_ROLE @event.parameters.ROLE_NAME:_SEED_ADMIN_ROLE"
  }

  type = "log_detection"
}

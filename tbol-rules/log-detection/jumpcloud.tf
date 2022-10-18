resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_l6i-dpj-wfa" {
  case {
    condition = "admin_login_no_mfa > 0"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a JumpCloud administrator authenticates without multi-factor authentication (MFA) enabled. This is not indicative of malicious activity, however as a best practice, administrator accounts should have MFA enabled.\n\n## Strategy\nThis rule monitors JumpCloud audit logs to detect when an admin user successfully authenticates to JumpCloud and the log indicates that `@mfa` is `false`.\n\n## Triage and response\n1. Reach out to the {{@usr.name}} to determine if the login was legitimate.\n2. If the login was legitimate, request that the user enables MFA.\n3. If the login wasn’t legitimate, rotate the credentials, enable MFA and triage an actions uncovered from step 1.\n4. Review all user accounts to ensure MFA is enabled.\n"
  name               = "[TBOL] Jumpcloud admin login without MFA"

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
    name            = "admin_login_no_mfa"
    query           = "source:jumpcloud @evt.name:admin_login_attempt @mfa:false @evt.outcome:true"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_equ-p7q-hzc" {
  case {
    status = "high"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect an Impossible Travel event with a JumpCloud administrator.\n\n## Strategy\nThe Impossible Travel detection type’s algorithm compares the GeoIP data of the last log and the current log to determine if the user (`@usr.name`) traveled more than 500km at over 1,000km/h.\n\n## Triage and response\n1. Determine if {@usr.name}} should be connecting from {{@impossible_travel.triggering_locations.first_location.city}}, {{@impossible_travel.triggering_locations.first_location.country}} and {{@impossible_travel.triggering_locations.second_location.city}}, {{@impossible_travel.triggering_locations.second_location.country}} in a short period of time.\n2. If the user should not be connecting from {{@impossible_travel.triggering_locations.first_location.city}}, {{@impossible_travel.triggering_locations.first_location.country}} or {{@impossible_travel.triggering_locations.second_location.city}}, {{@impossible_travel.triggering_locations.second_location.country}}, then consider isolating the account and reset credentials.\n3. Use the Cloud SIEM - User Investigation dashboard to audit any user actions that may have occurred after the illegitimate login."
  name               = "[TBOL] Jumpcloud admin triggered impossible travel scenario"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "impossible_travel"
    evaluation_window                 = "0"

    impossible_travel_options {
      baseline_user_locations = "true"
    }

    keep_alive          = "21600"
    max_signal_duration = "86400"
  }

  query {
    aggregation     = "geo_data"
    group_by_fields = ["@usr.email"]
    metric          = "@network.client.geoip"
    metrics         = ["@network.client.geoip"]
    name            = "impossible_travel_admin"
    query           = "source:jumpcloud @usr.type:admin"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_c2q-hzl-8ik" {
  case {
    condition = "system_admin_grant > 0"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\n\nDetect when a JumpCloud user grants administrative privileges on a user endpoint. This is not indicative of malicious activity, but detecting this event is valuable for auditing.\n\n## Strategy\n\nThis rule monitors JumpCloud audit logs to detect when a user triggers the `@evt.name` of `system_admin_grant`.\n\n## Triage and response\n\n1. Reach out to the admin making the change (`{{@usr.email}}`) to confirm that the user `(@usr.name`) should have administrative privileges on the specified resource (`@resource.name`).\n2. If the change was not authorized, reverify there are no other signals from the jumpcloud admin: {{@usr.email}} and the system (`@resource.name`).\n"
  name               = "[TBOL] Jumpcloud admin granted system privileges"

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
    name            = "system_admin_grant"
    query           = "source:jumpcloud @evt.name:system_admin_grant"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_szr-9jw-a6i" {
  case {
    condition = "policy_creation > 0"
    status    = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a JumpCloud policy is created. \n\n## Strategy\nThis rule lets you monitor the following JumpCloud event to detect when a policy is created:\n\n* `@evt.name:policy_create`\n\n## Triage and response\n1. Contact the JumpCloud administrator `{{@usr.email}}` to confirm if the policy creation was intended.\n2. If the change was **not** authorized, verify there are no other signals from the administrator:`{{@usr.email}}`."
  name               = "[TBOL] Jumpcloud policy created"

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
    name            = "policy_creation"
    query           = "source:jumpcloud @evt.name:policy_create"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_pph-pou-yad" {
  case {
    condition = "policy_update > 0"
    status    = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a JumpCloud policy is modified. \n\n## Strategy\nThis rule lets you monitor the following JumpCloud event to detect when a policy is modified:\n\n* `@evt.name:policy_update`\n\n## Triage and response\n1. Contact the JumpCloud administrator `{{@usr.email}}` to confirm if the policy modification(s) was intended.\n2. If the change was **not** authorized, verify there are no other signals from the administrator:`{{@usr.email}}`."
  name               = "[TBOL] Jumpcloud policy modified"

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
    name            = "policy_update"
    query           = "source:jumpcloud @evt.name:policy_update"
  }

  type = "log_detection"
}

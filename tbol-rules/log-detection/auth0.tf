resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_kds-umf-bvf" {
  case {
    condition = "breached_password > 0"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a user logs in with a breached password.\n\n## Strategy\nAuth0 logs an event when a user logs in with a breached password. When this event is detected, Datadog generates a `MEDIUM` severity Security Signal.\n\nYou can see more information on how Auth0 detects breached passwords on their [documentation][1].\n\n## Triage and response\n1. Inspect the policy and user location to see if this was a login from approved location\n2. See if 2FA was authenticated\n3. If the user was compromised, rotate user credentials.\n\n[1][https://auth0.com/docs/anomaly-detection/brute-force-protection]\n"
  name               = "[TBOL] Auth0 user logged in with a breached password"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "0"
    keep_alive                        = "0"
    max_signal_duration               = "0"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@usr.id"]
    name            = "breached_password"
    query           = "source:auth0 @evt.name:breached_password"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_jmc-nzf-f2v" {
  case {
    condition = "failed_login>5 \u0026\u0026 successful_login>=1"
    name      = "Successful"
    status    = "medium"
  }

  case {
    condition = "failed_login>10"
    name      = "Attempt"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect a brute force attack on a user. \n\n## Strategy\n**To determine a successful attempt:** Detect when the same user fails to login five times and then successfully logs in. This generates a `MEDIUM` severity signal.\n\n**To determine an unsuccessful attempt:** Detect when the same user fails to login five times. This generates an `INFO` severity signal.\n\n## Triage and response\n1. Inspect the logs to see if this was a valid login attempt.\n2. See if 2FA was authenticated\n3. If the user was compromised, rotate user credentials.\n\n"
  name               = "[TBOL] Brute force attack on an Auth0 user"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "600"
    keep_alive                        = "3600"
    max_signal_duration               = "86400"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@usr.id"]
    name            = "failed_login"
    query           = "source:auth0 @evt.name:(failed_login_incorrect_password OR failed_login_invalid_email_or_username)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@usr.id"]
    name            = "successful_login"
    query           = "source:auth0 @evt.name:success_login"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_iwc-0zr-ypd" {
  case {
    condition = "unique_users_failing_to_login>10 \u0026\u0026 successful_login>=1"
    name      = "Successful"
    status    = "high"
  }

  case {
    condition = "unique_users_failing_to_login>10"
    name      = "Attempt"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect Account Take Over (ATO) through credential stuffing attack.\n\n## Strategy\n**To determine a successful attempt:** Detect a high number of failed logins from at least ten unique users and at least one successful login for a user. This generates a `HIGH` severity signal.\n\n**To determine an unsuccessful attempt:** Detect a high number of failed logins from at least ten unique users. This generates an `INFO` severity signal.\n\n## Triage and response\n1. Inspect the logs to see if this was a valid login attempt.\n2. See if 2FA was authenticated\n3. If the user was compromised, rotate user credentials.\n\n## Changelog\n13 June 2022 - Updated Keep Alive window and evaluation window to reduce rule noise."
  name               = "[TBOL] Credential stuffing attack on Auth0"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "3600"
    keep_alive                        = "21600"
    max_signal_duration               = "86400"
  }

  query {
    aggregation     = "cardinality"
    distinct_fields = ["@usr.id"]
    group_by_fields = ["@network.client.ip"]
    name            = "unique_users_failing_to_login"
    query           = "source:auth0 @evt.name:(failed_login_incorrect_password OR failed_login_invalid_email_or_username)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@network.client.ip"]
    name            = "successful_login"
    query           = "source:auth0 @evt.name:success_login"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_f5q-0un-ahl" {
  case {
    status = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect an Impossible Travel event when two successful authentication events occur in a short time frame.\n\n## Strategy\nThe Impossible Travel detection type's algorithm compares the GeoIP data of the last log and the current log to determine if the user `{{@usr.name}}` traveled more than 500km at over 1,000km/hr.\n\n## Triage and response\n1. Determine if the user `{{@usr.name}}` should have authenticated from `{{@impossible_travel.triggering_locations.first_location.city}}, {{@impossible_travel.triggering_locations.first_location.country}}` and `{{@impossible_travel.triggering_locations.second_location.city}}, {{@impossible_travel.triggering_locations.second_location.country}}`.\n2. If `{{@user.name}}` should not authenticated from `{{@impossible_travel.triggering_locations.first_location.city}}, {{@impossible_travel.triggering_locations.first_location.country}}` and `{{@impossible_travel.triggering_locations.second_location.city}}, {{@impossible_travel.triggering_locations.second_location.country}}`, then consider isolating the account and reset credentials.\n3. Audit any instance actions that may have occurred after the illegitimate login.\n\n**NOTE** VPNs and other anonymous IPs are filtered out of this signal\n"
  name               = "[TBOL] Impossible Travel Auth0 login"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "impossible_travel"
    evaluation_window                 = "0"

    impossible_travel_options {
      baseline_user_locations = "false"
    }

    keep_alive          = "21600"
    max_signal_duration = "86400"
  }

  query {
    aggregation     = "geo_data"
    group_by_fields = ["@usr.name"]
    metric          = "@network.client.geoip"
    metrics         = ["@network.client.geoip"]
    name            = "auth0_impossible_travel"
    query           = "source:auth0 @evt.category:authentication  -@evt.outcome:failure -@threat_intel.results.category:anonymizer"
  }

  type = "log_detection"
}

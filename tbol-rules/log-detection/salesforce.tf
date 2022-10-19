resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_yqj-9wa-v8a" {
  case {
    status = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when there is a spike in Salesforce query results for a user. A large query can be an early warning sign of a user attempting to exfiltrate Salesforce data. \n\n## Strategy\nInspect and baseline Salesforce logs and determine if there is a spike in the number of rows returned (`@rows_returned`). \n\n## Triage and response\n1. Determine if the user should be legitimately performing large queries.\n"
  name               = "[TBOL] Anomalous amount of Salesforce query results"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "anomaly_detection"
    evaluation_window                 = "1800"
    keep_alive                        = "7200"
    max_signal_duration               = "86400"
  }

  query {
    aggregation     = "sum"
    group_by_fields = ["@usr.id"]
    metric          = "@rows_returned"
    metrics         = ["@rows_returned"]
    query           = "source:salesforce @rows_returned:*"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_2zb-rhj-kge" {
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
  message            = "## Goal\nDetect a brute force attack on a Salesforce user. \n\n## Strategy\n**To determine a successful attempt:** Detect when the same user fails to login five times and then successfully logs in. This generates a `MEDIUM` severity signal.\n\n**To determine an unsuccessful attempt:** Detect when the same user fails to login ten times. This generates an `INFO` severity signal.\n\n## Triage and response\n1. Inspect the logs to see if this was a valid login attempt.\n2. See if 2FA was authenticated.\n3. If the user was compromised, rotate user credentials.\n"
  name               = "[TBOL] Salesforce Brute force attack on user"

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
    name            = "failed_login"
    query           = "source:salesforce @status:\"Invalid Password\""
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@usr.id"]
    name            = "successful_login"
    query           = "source:salesforce @status:Success"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_kec-tmb-w0f" {
  case {
    condition = "unique_users_failing_to_login > 10 \u0026\u0026 successful_login>=1"
    name      = "Successful"
    status    = "high"
  }

  case {
    condition = "unique_users_failing_to_login > 10 "
    name      = "Attempt"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect an account take over (ATO) through credential stuffing attack against a Salesforce account.\n\nA credential stuffing attack is used to gain initial access by compromising user accounts.\n\nThe attacker obtains a list of compromised usernames and passwords from a previous user database breach, phishing attempt, or other means. Then, they use the list of username and passwords to attempt to login to accounts on your application.\n\nIt is common for an attacker to use multiple IP addresses to target your application in order to distribute the attack load for load balancing purposes, to make it more difficult to detect, or make it more difficult to block.\n\n## Strategy\n**To determine a successful attempt:** Detect a high number of failed logins from at least ten unique users and at least one successful login for a user within a period of time from the same IP address.\n\n**To determine an unsuccessful attempt:** Detect a high number of failed logins from at least ten unique users within a period of time from the same IP address.\n\n## Triage and response\n\n1. Determine if it is a legitimate attack or a false positive.\n2. Determine compromised users.\n3. Remediate compromised user accounts.\n"
  name               = "[TBOL] Credential stuffing attack on Salesforce"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "cardinality"
    distinct_fields = ["@usr.email"]
    group_by_fields = ["@network.client.ip"]
    name            = "unique_users_failing_to_login"
    query           = "source:salesforce @status:\"Invalid Password\""
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@network.client.ip"]
    name            = "successful_login"
    query           = "source:salesforce @status:\"Success\""
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_y05-jo7-0ln" {
  case {
    status = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when there is a significant increase in deleted records in Salesforce.\n\n## Strategy\nInspect and baseline Salesforce logs and determine if there is a significant increase in successful (`@evt.outcome:Success`) delete operations (`@operation:Delete`).\n\n## Triage and response\n1. Determine if the user should be legitimately deleting Salesforce records.\n"
  name               = "[TBOL] Anomalous amount of Salesforce records deleted"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "anomaly_detection"
    evaluation_window                 = "1800"
    keep_alive                        = "7200"
    max_signal_duration               = "86400"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@usr.id"]
    query           = "source:salesforce @operation:Delete @evt.outcome:Success"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_m1a-5iy-awv" {
  case {
    condition = "disabled_login > 1"
    name      = "Single Attempt"
    status    = "info"
  }

  case {
    condition = "disabled_login > 10"
    name      = "Multiple Attempts"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a disabled account attempts to log into Salesforce\n\n## Strategy\nInspect Salesforce logs and determine if there is a login attempt (`@evt.name:LoginEvent`) from from a disabled account (`@status:\\\"User is Inactive\\\"`). If more than ten attempts to authenticate to a disabled account a `MEDIUM` severity signal is created.\n\n## Triage and response\n1. Determine if the IP (`@network.client.ip`) has attempted to log into other accounts.\n"
  name               = "[TBOL] Salesforce Login from Disabled Account"

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
    name            = "disabled_login"
    query           = "source:salesforce @evt.name:LoginEvent @status:\"User is Inactive\""
  }

  type = "log_detection"
}

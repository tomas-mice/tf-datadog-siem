resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_jzl-fyt-eyf" {
  case {
    condition = "a > 0"
    status    = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an S3 bucket has a lifecycle configuration set with an expiration policy of less than 90 days.\n\n## Strategy\nLook for `@requestParameters.LifecycleConfiguration.Rule.Expiration.Days:<90` in your Cloudtrail logs.\n\n**NOTE**: This rule should be set to logs that this policy applies to. The `@requestParameters.LifecycleConfiguration.Rule.Expiration.Days` key path must be set as a measure to do a query.\n\n\n## Triage \u0026 response\n1. Determine if `{{@evt.name}}` should have occurred on the `{{@requestParameters.bucketName}}` by `username:` `{{@userIdentity.sessionContext.sessionIssuer.userName}}`, `accountId:` `{{@usr.account_id}}` of `type:` `{{@userIdentity.assumed_role}}` and that the `{{@requestParameters.bucketName}}` bucket should have a file expiration of less than 90 days.\n2. If `{{@requestParameters.bucketName}}` is equal to `{{@aws.s3.bucket}}`, the CloudTrail bucket, consider escalating to higher severity and investigating further."
  name               = "[TBOL] An AWS S3 bucket lifecycle policy expiration is set to < 90 days"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "7200"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@requestParameters.bucketName"]
    query           = "@evt.name:PutBucketLifecycle -status:error @eventSource:s3.amazonaws.com @requestParameters.LifecycleConfiguration.Rule.Expiration.Days:<90"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_m0f-no8-lfa" {
  case {
    condition = "sqreen_critical_incidents > 0"
    name      = "Critical"
    status    = "critical"
  }

  case {
    condition = "sqreen_major_incidents > 0"
    name      = "Major"
    status    = "high"
  }

  case {
    condition = "sqreen_minor_incidents > 0"
    name      = "Minor"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect a threat on your application.\n\n## Strategy\nThis rule creates a signal for every security incident created by Sqreen.\n\n## Triage and response\n1. Review the incident on the [Sqreen dashboard][1].\n\n[1]: https://my.sqreen.com/incidents\n\n## Changelog\n23 June 2022 - Updated groupby count to reduce rule noise."
  name               = "[TBOL] Security Incident Detected by Sqreen"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "0"
    keep_alive                        = "0"
    max_signal_duration               = "0"
  }

  query {
    aggregation     = "cardinality"
    distinct_fields = ["@sqreen.payload.incident_id"]
    group_by_fields = ["service", "@sqreen.payload.name"]
    name            = "sqreen_critical_incidents"
    query           = "@evt.name:sq.dd0.incident  @sqreen.payload.severity:critical @sqreen.payload.event_type:create"
  }

  query {
    aggregation     = "cardinality"
    distinct_fields = ["@sqreen.payload.incident_id"]
    group_by_fields = ["service", "@sqreen.payload.name"]
    name            = "sqreen_major_incidents"
    query           = "@evt.name:sq.dd0.incident  @sqreen.payload.severity:major @sqreen.payload.event_type:create"
  }

  query {
    aggregation     = "cardinality"
    distinct_fields = ["@sqreen.payload.incident_id"]
    group_by_fields = ["service", "@sqreen.payload.name"]
    name            = "sqreen_minor_incidents"
    query           = "@evt.name:sq.dd0.incident  @sqreen.payload.severity:minor @sqreen.payload.event_type:create"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_5c5-r16-qza" {
  case {
    status = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect an Impossible Travel event when a `@userIdentity.type:` `{{@userIdentity.type}}` performs a `consoleLogin` with a multi-factor authentication (MFA) device.\n\n## Strategy\nThe Impossible Travel detection type's algorithm compares the GeoIP data of the last log and the current log to determine if the user with `@userIdentity.session_name:` `{{@userIdentity.session_name}}` traveled more than 500km at over 1,000km/h and the account does not have MFA enabled.\n\n## Triage and response\n1. Determine if `{{@userIdentity.session_name}}` should be connecting from  `{{@impossible_travel.triggering_locations.first_location.city}}, {{@impossible_travel.triggering_locations.first_location.country}}` and `{{@impossible_travel.triggering_locations.second_location.city}}, {{@impossible_travel.triggering_locations.second_location.country}}` in a short period of time.\n2. If the user should not be connecting from `{{@impossible_travel.triggering_locations.first_location.city}}, {{@impossible_travel.triggering_locations.first_location.country}}` and `{{@impossible_travel.triggering_locations.second_location.city}}, {{@impossible_travel.triggering_locations.second_location.country}}`, then consider isolating the account and reset credentials.\n3. Use the Cloud SIEM - User Investigation dashboard to audit any user actions that may have occurred after the illegitimate login. \n\n## Changelog\n10 Mar 2022 - Rule updated.\n"
  name               = "[TBOL] AWS ConsoleLogin without MFA triggered Impossible Travel scenario"

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
    group_by_fields = ["@userIdentity.session_name"]
    metric          = "@network.client.geoip"
    metrics         = ["@network.client.geoip"]
    name            = "impossible_travel_no_mfa"
    query           = "@evt.name:ConsoleLogin -@level:Error @userIdentity.sessionContext.attributes.mfaAuthenticated:false -@threat_intel.results.category:anonymizer"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_iwr-a2p-mbj" {
  case {
    name   = "impossible travel event for ConsoleLogin with MFA"
    status = "high"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect an Impossible Travel event when a `@userIdentity.type:` `{{@userIdentity.type}}` performs a `consoleLogin` with a multi-factor authentication (MFA) device.\n\n## Strategy\nThe Impossible Travel detection type's algorithm compares the GeoIP data of the last log and the current log to determine if the user with `@userIdentity.session_name:` `{{@userIdentity.session_name}}` traveled more than 500km at over 1,000km/h and the user used MFA.\n\n## Triage and response\n1. Determine if `{{@userIdentity.session_name}}` should be connecting from  `{{@impossible_travel.triggering_locations.first_location.city}}, {{@impossible_travel.triggering_locations.first_location.country}}` and `{{@impossible_travel.triggering_locations.second_location.city}}, {{@impossible_travel.triggering_locations.second_location.country}}` in a short period of time.\n2. If the user should not be connecting from `{{@impossible_travel.triggering_locations.first_location.city}}, {{@impossible_travel.triggering_locations.first_location.country}}` and `{{@impossible_travel.triggering_locations.second_location.city}}, {{@impossible_travel.triggering_locations.second_location.country}}`, then consider isolating the account and reset credentials.\n3. Use the Cloud SIEM - User Investigation dashboard to audit any user actions that may have occurred after the illegitimate login. \n\n## Changelog\n10 Mar 2022 - Rule updated.\n"
  name               = "[TBOL] AWS ConsoleLogin with MFA triggered Impossible Travel scenario"

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
    group_by_fields = ["@userIdentity.session_name"]
    metric          = "@network.client.geoip"
    metrics         = ["@network.client.geoip"]
    name            = "impossible_travel_mfa"
    query           = "@evt.name:ConsoleLogin -@level:Error @userIdentity.sessionContext.attributes.mfaAuthenticated:true -@threat_intel.results.category:anonymizer"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_cwf-nwr-nsi" {
  case {
    status = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a user logs into an application that is using Sqreen from a new country.\n\n## Strategy\nThis rule lets you monitor when a user logs into an application from a country that has not been seen before.\n\n## Triage and response\n1. Review the user activity on the [Sqreen dashboard][1].\n\n[1]: https://my.sqreen.com/application/goto/users/\n"
  name               = "[TBOL] User Logged into an Application from a New Country"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "new_value"
    evaluation_window                 = "0"
    keep_alive                        = "0"
    max_signal_duration               = "86400"

    new_value_options {
      forget_after       = "28"
      learning_duration  = "7"
      learning_method    = "duration"
      learning_threshold = "0"
    }
  }

  query {
    aggregation     = "new_value"
    group_by_fields = ["@usr.id"]
    metric          = "@network.client.geoip.country.name"
    metrics         = ["@network.client.geoip.country.name"]
    query           = "@evt.name:sq.dd0.user_event.login @sqreen.payload.success:true"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_irc-lrt-pmc" {
  case {
    condition     = "a>5 \u0026\u0026 b>0"
    name          = "Successful"
    notifications = ["@slack-secops"]
    status        = "high"
  }

  case {
    condition = "a>5"
    name      = "Attempted"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect an account take over (ATO) through brute force attempts.\n\n## Strategy\nTo determine a successful attempt: Detect a high amount of failed logins and at least one successful login for a given IP address. This will generate a `HIGH` severity signal.\nTo determine an attempt: Detect a high amount of failed logins for a given IP address. This will generate an `INFO severity signal.\n\n## Triage and response\n1. Inspect the logs to see if this was a valid login attempt.\n2. See if 2FA was authenticated.\n3. If the user was compromised, rotate user credentials.\n"
  name               = "[TBOL] TEMPLATE - Brute Force Attack Grouped By IP"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "7200"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@usr.name"]
    query           = "@evt.name:authentication @evt.outcome:failure"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@usr.name"]
    query           = "@evt.name:authentication @evt.outcome:success"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_y21-t2c-sgm" {
  case {
    condition = "unique_users_failing_to_login>50 \u0026\u0026 successful_login>=1"
    name      = "Successful - Greater than 50"
    status    = "high"
  }

  case {
    condition = "unique_users_failing_to_login>25 \u0026\u0026 successful_login>=1"
    name      = "Successful"
    status    = "medium"
  }

  case {
    condition = "unique_users_failing_to_login>25"
    name      = "Attempt"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect Account Take Over (ATO) through credential stuffing attack.\n\nA credential stuffing attack is used to gain initial access by compromising user accounts.\n\nThe attacker obtains a list of compromised usernames and passwords from a previous user database breach, phishing attempt, or other means. Then, they use the list of username and passwords to attempt to login to accounts on your application.\n\nIt is common for an attacker to use multiple IP addresses to target your application in order to distribute the attack load for load balancing purposes, to make it more difficult to detect, or make it more difficult to block.\n\n## Strategy\n**To determine a successful attempt:** Detect a high number of failed logins from at least 25 unique users and at least one successful login for a user within a period of time from the same IP address.\n\n**To determine an unsuccessful attempt:** Detect a high number of failed logins from at least ten unique users within a period of time from the same IP address.\n\n## Triage and response\n\nUse [this Datadog runbook](https://app.datadoghq.com/notebook/credentialstuffingrunbook) to assist in your investigation.\n\n1. Determine if it is a legitimate attack or a false positive\n2. Determine compromised users\n3. Remediate compromised user accounts\n"
  name               = "[TBOL] Credential stuffing attack"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "1800"
    keep_alive                        = "3600"
    max_signal_duration               = "86400"
  }

  query {
    aggregation     = "cardinality"
    distinct_fields = ["@usr.id"]
    group_by_fields = ["@network.client.ip"]
    name            = "unique_users_failing_to_login"
    query           = "@evt.category:authentication @evt.outcome:failure"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@network.client.ip"]
    name            = "successful_login"
    query           = "@evt.category:authentication @evt.outcome:success"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_0j7-7yo-vr6" {
  case {
    condition = "refresh_token_reuse_threat > 0"
    name      = "Threat suspected"
    status    = "medium"
  }

  case {
    condition = "refresh_token_reuse > 0"
    name      = "Threat unlikely"
    status    = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an Okta [refresh token][1] is reused.\n\n## Strategy\nThis rule lets you monitor the following Okta events when token reuse is detected:\n\n* `app.oauth2.token.detect_reuse`\n* `app.oauth2.as.token.detect_reuse`\n\nAn attacker that has access to a refresh token could query the organization's authorization server `/token` endpoint to obtain additional access tokens. The additional access tokens potentially allow the attacker to get unauthorized access to applications.\n\n## Triage and response\n1. Determine if the source IP `{{@network.client.ip}}` is anomalous within the organization:\n    * Does threat intelligence indicate that this IP has been associated with malicious activity?\n    * Is the geo-location or ASN uncommon for the organization?\n    * Has the IP created a `app.oauth2.token.detect_reuse` or `app.oauth2.as.token.detect_reuse` event previously?\n2. If the token reuse event has been determined to be malicious, carry out the following actions:\n    * [Revoke compromised tokens][2].\n    * Recycle the credentials of any impacted clients.\n    * Begin your company's incident response process and investigate.\n\n[1]: https://developer.okta.com/docs/guides/refresh-tokens/main/\n[2]: https://developer.okta.com/docs/guides/revoke-tokens/main/"
  name               = "[TBOL] Okta one-time refresh token reused"

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
    name            = "refresh_token_reuse"
    query           = "source:okta @evt.name:(app.oauth2.token.detect_reuse OR app.oauth2.as.token.detect_reuse) @debugContext.debugData.threatSuspected:false"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@usr.email"]
    name            = "refresh_token_reuse_threat"
    query           = "source:okta @evt.name:(app.oauth2.token.detect_reuse OR app.oauth2.as.token.detect_reuse) @debugContext.debugData.threatSuspected:true"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_3c8-put-5x3" {
  case {
    condition = "request_blocked > 10"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a request is blocked due to a block list rule (such as an IP network zone or location rule).\n\n## Strategy\nThis rule lets you monitor the following Okta events to detect when a malicious IP address communicates with your Okta account:\n\n* `security.request.blocked`\n\n## Triage \u0026 Response\n1. Verify with the owner of `{{@usr.name}}` that they were attempting a request to `{{@target_app}}`.\n2. If the request cannot be verified with the user, correlate with other log sources to see if the blocked IP in the `title` of `{{@title}}` has communicated elsewhere on the network."
  name               = "[TBOL] Okta blocked numerous requests from a malicious IP"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@network.client.ip", "@target_app"]
    name            = "request_blocked"
    query           = "source:okta @evt.name:security.request.blocked @evt.outcome:SUCCESS"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_5rg-1u3-yny" {
  case {
    condition = "a > 0"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a user attempts to bypass multi-factor authentication (MFA).\n\n## Strategy\nThis rule lets you monitor the following Okta events to detect when a user attempts to bypass MFA:\n\n* `user.mfa.attempt_bypass`\n\n## Triage and response\n1. Contact the user who attempted to bypass MFA and ensure the request was legitimate.\n"
  name               = "[TBOL] Okta MFA Bypass Attempted"

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
    query           = "source:okta @evt.name:user.mfa.attempt_bypass"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_8gm-lct-wco" {
  case {
    condition = "user_session_impersonation_initiate > 0"
    name      = "Session initiated"
    status    = "info"
  }

  case {
    condition = "user_session_impersonation_end > 0"
    name      = "Session ended"
    status    = "info"
  }

  case {
    condition = "user_session_impersonation_grant > 0"
    name      = "Session granted"
    status    = "info"
  }

  case {
    condition = "user_session_impersonation_extend > 0"
    name      = "Session extended"
    status    = "info"
  }

  case {
    condition = "user_session_impersonation_revoke > 0"
    name      = "Session revoked"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect an Okta session impersonation.\n\n## Strategy\nThis rule lets you monitor the following Okta events to detect a user session impersonation:\n\n* `user.session.impersonation.initiate`\n* `user.session.impersonation.end`\n* `user.session.impersonation.grant`\n* `user.session.impersonation.extend`\n* `user.session.impersonation.revoke`\n\nThese events indicate that the user: `{{@usr.email}}` has the effective permissions of the impersonated user. This is likely to occur through [Okta support access][1]. This [blog][2] illustrates the potential impact an attacker can cause by impersonation session.\n\n## Triage and response\n1. Contact your Okta administrator to ensure the user: `{{@usr.email}}` is authorized to impersonate a user session.\n2. If the user impersonation session is not legitimate:\n    * Task your Okta administrator to end the impersonation session.\n    * Investigate the actions taken by the user `{{@usr.email}}` during the session and revert back to the last known good state.\n    * Begin your company's incident response process and investigate.\n\n[1]: https://support.okta.com/help/s/article/Granting-Access-to-Okta-Support?language=en_US\n[2]: https://blog.cloudflare.com/cloudflare-investigation-of-the-january-2022-okta-compromise/"
  name               = "[TBOL] Okta Impersonation"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "7200"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@usr.email"]
    name            = "user_session_impersonation_initiate"
    query           = "source:okta @evt.name:user.session.impersonation.initiate"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@usr.email"]
    name            = "user_session_impersonation_end"
    query           = "source:okta @evt.name:user.session.impersonation.end"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@usr.email"]
    name            = "user_session_impersonation_grant"
    query           = "source:okta @evt.name:user.session.impersonation.grant"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@usr.email"]
    name            = "user_session_impersonation_extend"
    query           = "source:okta @evt.name:user.session.impersonation.extend"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@usr.email"]
    name            = "user_session_impersonation_revoke"
    query           = "source:okta @evt.name:user.session.impersonation.revoke"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_dxx-i0a-pmk" {
  case {
    condition = "mfa_reset_success > 0"
    name      = "Succeeded"
    status    = "low"
  }

  case {
    condition = "mfa_reset_failed > 0"
    name      = "Failed"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when the multi-factor authentication (MFA) factors for an enrolled Okta user are reset.\n\n## Strategy\nThis rule lets you monitor the following Okta event to determine when a user's MFA factors are reset:\n\n* `user.mfa.factor.reset_all`\n\nAn attacker may attempt to reset MFA factors in a bid to access other user accounts by registering new attacker-controlled MFA factors.\n\n## Triage and response\n1. Determine if the user: `{{@usr.email}}` should have reset the MFA factors of the targeted user.\n2. If the change was not made by the user:\n    * Disable the affected user accounts.\n    * Rotate user credentials.\n    * Return targeted users MFA factors to the last known good state.\n    * Begin your organization's incident response process and investigate.\n3. If the change was made by the user:\n    * Determine if the user was authorized to make that change.\n    * If **Yes**, ensure the targeted user has new MFA factors assigned in accordance with organization policies.\n    * If **No**, verify there are no other signals from the Okta administrator: `{{@usr.email}}`."
  name               = "[TBOL] Okta MFA reset for user"

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
    name            = "mfa_reset_success"
    query           = "source:okta @evt.name:user.mfa.factor.reset_all @evt.outcome:SUCCESS"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@usr.email"]
    name            = "mfa_reset_failed"
    query           = "source:okta @evt.name:user.mfa.factor.reset_all @evt.outcome:FAILURE"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_emu-s99-ejm" {
  case {
    condition = "a > 0"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an IP address identified as malicious by Okta's ThreatInsight communicates with your Okta account.\n\n## Strategy\nThis rule lets you monitor the following Okta events to detect when a malicious IP address communicates with your Okta account:\n\n* `security.threat.detected`\n\n## Triage and response\n1. Determine if the `@usr.email` is `Unknown` or is an authenticated user.\n2. If the user is authenticated, conduct an investigation to determine if the IP address that is communicating with Okta is the user's IP address, or if the account is compromised.\n3. Consider switching ThreatInsight from `log mode` to `log and block mode` to block future requests from IP addresses on the ThreatInsight threat intelligence list.\n"
  name               = "[TBOL] Malicious IP Communicating with Okta"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@network.client.ip"]
    query           = "source:okta @evt.name:security.threat.detected @evt.outcome:ALLOW"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_ii1-y88-7nm" {
  case {
    condition = "privilege_grant > 0"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when administrative privileges are provisioned to an Okta user.\n\n## Strategy\nThis rule lets you monitor the following Okta event to detect when administrative privileges are provisioned:\n\n* `user.account.privilege.grant`\n\n## Triage and response\n1. Contact the Okta administrator: `{{@usr.email}}` to confirm that the user or users should have administrative privileges.\n2. If the change was **not** authorized, verify there are no other signals from the Okta administrator: `{{@usr.email}}`."
  name               = "[TBOL] Okta administrator role assigned to user"

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
    name            = "privilege_grant"
    query           = "source:okta @evt.name:user.account.privilege.grant"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_kpr-jbj-4pl" {
  case {
    condition = "a > 0"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a new Okta API token is created.\n\n## Strategy\nThis rule lets you monitor the following Okta event to detect when a new Okta API token is created:\n\n* `system.api_token.create`\n\n## Triage and response\n1. Contact the user who created the API token and ensure that the API token is needed.\n"
  name               = "[TBOL] Okta API Token Created or Enabled"

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
    query           = "source:okta @evt.name:system.api_token.create"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_r8r-zwm-qda" {
  case {
    condition = "policy_rule_deleted > 0"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an Okta policy rule is deleted.\n\n## Strategy\nThis rule lets you monitor the following Okta event to detect when a policy rule is deleted:\n\n* `policy.rule.delete`\n\n## Triage and response\n1. Contact the Okta administrator to confirm that the user: `{{@usr.email}}` should be deleting policy rules.\n2. If the change was **not** authorized, verify there are no other signals from the user: `{{@usr.email}}`."
  name               = "[TBOL] Okta policy rule deleted"

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
    name            = "policy_rule_deleted"
    query           = "source:okta @evt.name:policy.rule.delete @evt.outcome:SUCCESS"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_urb-j7h-l6e" {
  case {
    condition = "a > 0"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a user is denied access to an app.\n\n## Strategy\nThis rule lets you monitor the following Okta events to detect when a user is denied access to an app:\n\n* `app.generic.unauth_app_access_attempt`\n\n## Triage and response\n1. Determine whether or not the user should have access to this app.\n2. Contact the user to determine whether they attempted to access this app or whether their account is compromised.\n"
  name               = "[TBOL] Okta User Attempted to Access Unauthorized App"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@usr.email", "@target_app"]
    query           = "source:okta @evt.name:app.generic.unauth_app_access_attempt"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_wnc-sea-1xk" {
  case {
    condition = "a > 0"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a user is denied access to sign on to an app based on sign-on policy.\n\n## Strategy\nThis rule lets you monitor the following Okta events to detect when a user is denied access to sign on to an app based on sign-on policy:\n\n* `application.policy.sign_on.deny_access`\n\n## Triage and response\n1. Inspect the `@target` array to determine why the user was denied access to sign on.\n2. Contact the user to determine whether they attempted to access this app or whether their account is compromised.\n"
  name               = "[TBOL] Okta User Access Denied to Sign On"

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
    query           = "source:okta @evt.name:application.policy.sign_on.deny_access"
  }

  type = "log_detection"
}

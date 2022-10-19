resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_002-tmj-qzp" {
  case {
    condition = "a > 0"
    status    = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a user shares a Microsoft 365 Sharepoint document with a guest.\n\n## Strategy\nThis rule monitors the Microsoft 365 logs for the event name `SharingInvitationCreated` when the `TargetUserOrGroupType` is `Guest`.\n\n## Triage and response\n1. Determine whether this document should be shared with the external user.\n"
  name               = "[TBOL] Microsoft 365 SharePoint object shared with guest"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@TargetUserOrGroupName", "@ObjectId"]
    query           = "source:microsoft-365 service:SharePoint @evt.name:(SharingInvitationCreated) @TargetUserOrGroupType:Guest"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_0oo-gvu-wbp" {
  case {
    status = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a Microsoft 365 user downloads an anomalous amount of files. This could be an indicator of data exfilteration.\n\n## Strategy\nMonitor Microsoft 365 audit logs to look for an anomalous amount of logs with an `@evt.name` value of `@evt.name:FileDownloaded`.\n\n## Triage and response\n1. Determine if the user `{{@usr.email}}` intended to download the files.\n2. If `{{@usr.email}}` is not responsible for file downloads, investigate `{{@usr.email}}` for anomalous activity. If necessary, initiate your company's incident response (IR) process."
  name               = "[TBOL] Microsoft 365 Anomalous Amount of Downloaded files"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "anomaly_detection"
    evaluation_window                 = "1800"
    keep_alive                        = "1800"
    max_signal_duration               = "1800"
  }

  query {
    aggregation     = "cardinality"
    distinct_fields = ["@SourceFileName"]
    group_by_fields = ["@usr.id"]
    name            = "files_downloaded"
    query           = "source:microsoft-365 @evt.name:FileDownloaded"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_249-hs0-qic" {
  case {
    status = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a new Microsoft 365 teams app is installed as a means of establishing persistence.\n\n## Strategy\nMonitor Microsoft 365 audit logs to look for events with an `@evt.name` value of `AppInstalled`, where the `AddOnType` has a value of `4` and a new `@AddOnName` is observed.\n\n## Triage and response\n1. Determine if the user `{{@usr.email}}` intended to install `{{@AddOnName}}`.\n2. If `{{@usr.email}}` is not responsible for installing `{{@AddOnName}}`, investigate `{{@usr.email}}` for anomalous activity. If necessary, initiate your company's incident response (IR) process."
  name               = "[TBOL] A new Microsoft 365 Teams app is observed"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "new_value"
    evaluation_window                 = "0"
    keep_alive                        = "0"
    max_signal_duration               = "0"

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
    metric          = "@AddOnName"
    metrics         = ["@AddOnName"]
    query           = "source:microsoft-365 @evt.name:AppInstalled @AddOnType:4"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_2js-obz-qoo" {
  case {
    condition = "azure_ad_successful_consent_to_application > 0 || o365_successful_consent_to_application > 0"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetects when a user grants an application consent to access their data. An adversary may create an Azure-registered application to access data such as contact information, emails, or documents.\n\n## Strategy\nMonitor Azure AD Audit logs for the following `@evt.name`:\n\n* `Consent to application`\n\nMonitor Microsoft 365 Audit logs for the following `@evt.name`:\n\n* `Consent to application.`\n\nBecause these are thirty-party applications external to the organization, normal remediation steps like resetting passwords for breached accounts or requiring Multi-Factor Authentication (MFA) on accounts are not effective against this type of attack.\n\n## Triage and response\n1. See the official [Microsoft playbook][1] on responding to a potential Illicit Consent Grant.\n2. If the activity is benign:\n    * Use the linked blog post in the suggested actions panel to tune out false positives.\n\n[1]: https://docs.microsoft.com/en-us/microsoft-365/security/office-365-security/detect-and-remediate-illicit-consent-grants?view=o365-worldwide"
  name               = "[TBOL] Potential Illicit Consent Grant attack via Azure registered application"

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
    name            = "azure_ad_successful_consent_to_application"
    query           = "source:azure.activedirectory @evt.category:AuditLogs @evt.name:\"Consent to application\" @evt.outcome:success"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@usr.id"]
    name            = "o365_successful_consent_to_application"
    query           = "source:microsoft-365 @evt.category:AuditLogs @evt.name:\"Consent to application.\" @evt.outcome:Success"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_cdk-uhd-jav" {
  case {
    condition = "azure_ad_trusted_domain_modified > 0 || m365_trusted_domain_modified > 0"
    status    = "critical"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\n\nDetects when a user creates or modifies a trusted domain object in Microsoft 365.\n\n## Strategy\n\nMonitor Azure AD Audit logs for the following `@evt.name`:\n\n- `Set federation settings on domain`\n- `Set domain authentication`\n\nMonitor Microsoft 365 Audit logs for the following `@evt.name`:\n\n- `Set federation settings on domain.`\n- `Set domain authentication.`\n\nAn attacker can create a new attacker-controlled domain as federated or modify the existing federation settings for a domain by configuring a new, secondary signing certificate. Both of these techniques would allow the attacker to authenticate as any user bypassing authentication requirements like a valid password or MFA.\n\n## Triage and response\n\n1. Determine if `{{@usr.id}}` should have made a `{{@evt.name}}` API call.\n2. If the API call was not made by the user:\n   - Remove the suspicious domain or settings.\n   - Begin your organization's Incident Response (IR) process.\n3. If the API call was made by the user:\n   - Ensure the change was authorized."
  name               = "[TBOL] Microsoft 365 - Modification of Trusted Domain"

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
    name            = "azure_ad_trusted_domain_modified"
    query           = "source:azure.activedirectory @evt.name:(\"Set domain authentication\" OR \"Set domain authentication \" OR \"Set federation settings on domain\" OR \"Set federation settings on domain \") @evt.category:AuditLogs"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@usr.id"]
    name            = "m365_trusted_domain_modified"
    query           = "source:microsoft-365 @evt.name:(\"Set domain authentication.\" OR \"Set domain authentication. \" OR \"Set federation settings on domain.\" OR \"Set federation settings on domain. \")"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_cpl-9ud-je5" {
  case {
    status = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a new Microsoft 365 app is installed as a means of establishing persistence.\n\n## Strategy\nMonitor Microsoft 365 audit logs to look for events with an `@evt.name` value of `Add application.` and event `@evt.outcome` of `Success`.\n\n## Triage and response\n1. Determine if the user `{{@usr.email}}` intended to install `{{@ObjectId}}`.\n2. If `{{@usr.email}}` is not responsible for installing `{{@ObjectId}}`, investigate `{{@usr.email}}` for anomalous activity. If necessary, initiate your company's incident response (IR) process."
  name               = "[TBOL] A new Microsoft 365 application was installed"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "new_value"
    evaluation_window                 = "0"
    keep_alive                        = "0"
    max_signal_duration               = "0"

    new_value_options {
      forget_after       = "28"
      learning_duration  = "7"
      learning_method    = "duration"
      learning_threshold = "0"
    }
  }

  query {
    aggregation     = "new_value"
    group_by_fields = ["@ObjectId", "@usr.id"]
    metric          = "@ObjectId"
    metrics         = ["@ObjectId"]
    query           = "source:microsoft-365 @evt.name:\"Add application.\" @evt.outcome:Success"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_drz-pws-zvy" {
  case {
    status = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect an Impossible Travel event by a user logging in to Microsoft Exchange.\n\n## Strategy\nThe Impossible Travel detection type’s algorithm compares the GeoIP data of the last and the current Microsoft-365 mailbox login event (`@evt.name:MailboxLogin`) to determine if the user `{{@usr.name}}` traveled more than 500km at over 1,000km/hr.\n\n## Triage and response\n1. Determine if `{{@usr.name}}` should be connecting from `{{@impossible_travel.triggering_locations.first_location.city}}, {{@impossible_travel.triggering_locations.first_location.country}}` and `{{@impossible_travel.triggering_locations.second_location.city}}, {{@impossible_travel.triggering_locations.second_location.country}}` in a short period of time.\n2. If the user should not be connecting from `{{@impossible_travel.triggering_locations.first_location.city}}, {{@impossible_travel.triggering_locations.first_location.country}}` and `{{@impossible_travel.triggering_locations.second_location.city}}, {{@impossible_travel.triggering_locations.second_location.country}}`, then consider isolating the account and reset credentials.\n3. Use the Cloud SIEM - User Investigation dashboard to audit any user actions that may have occurred after the illegitimate login. "
  name               = "[TBOL] Abnormal successful Microsoft 365 Exchange login event"

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
    group_by_fields = ["@usr.email"]
    metric          = "@network.client.geoip"
    metrics         = ["@network.client.geoip"]
    name            = "impossible_travel_mfa"
    query           = "source:microsoft-365 service:Exchange @evt.name:MailboxLogin @evt.outcome:Succeeded @threat_intel.results.category:*"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_gty-me3-gjm" {
  case {
    condition = "a > 0"
    status    = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a user installs an app to Microsoft 365 Teams.\n\n## Strategy\nThis rule monitors the Microsoft 365 logs for the event name `AppInstalled`.\n\n## Triage and response\n1. Determine whether this app should be installed to Microsoft 365 teams.\n"
  name               = "[TBOL] Microsoft 365 Teams app installed"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@AddOnName"]
    query           = "source:microsoft-365 service:MicrosoftTeams @evt.name:AppInstalled"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_gw4-yjo-4dz" {
  case {
    status = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an anomalous amount of emails are deleted from Microsoft 365 Exchange.\n\n## Strategy\nMonitor Microsoft 365 Exchange audit logs to look for events with an `@evt.name` value of `HardDelete`, where the `@Folder.Path` is the inbox (`*Inbox*`).\n\n## Triage and response\n1. Determine if the user `{{@usr.id}}` intended to delete the observed emails.\n2. If `{{@usr.id}}` is not responsible for the email deletions, investigate `{{@usr.id}}` for anomalous activity. If necessary, initiate your company's incident response (IR) process."
  name               = "[TBOL] Microsoft 365 Anomalous Amount of Deleted Emails"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "anomaly_detection"
    evaluation_window                 = "1800"
    keep_alive                        = "1800"
    max_signal_duration               = "1800"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@usr.id"]
    query           = "source:microsoft-365 @evt.name:HardDelete @Folder.Path:*Inbox*"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_jxr-vin-cro" {
  case {
    condition = "a > 0"
    status    = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a user creates an anonymous link for a Microsoft 365 document in OneDrive. This would allow any unauthenticated user to access this document, if they had the link.\n\n## Strategy\nThis rule monitors the Microsoft 365 logs for the event name `AnonymousLinkCreated`.\n\n## Triage and response\n1. Determine whether this document should be available anonymously.\n"
  name               = "[TBOL] Microsoft 365 OneDrive Anonymous Link Created"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@usr.id", "@ObjectId"]
    query           = "source:microsoft-365 service:OneDrive @evt.name:AnonymousLinkCreated"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_ndi-bm6-27v" {
  case {
    condition = "unified_audit_disabled > 0"
    name      = "Unified Audit Logging Disabled"
    status    = "high"
  }

  case {
    condition = "admin_audit_disabled > 0"
    name      = "Admin Audit Logging Disabled"
    status    = "high"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when admin or unified audit logging is disabled. An adversary or insider threat can disable audit logging as a means of defense evasion.\n\n## Strategy\nMonitor Microsoft 365 audit logs to look for events with an `@evt.name` value of `Set-AdminAuditLogConfig`, where `@Parameters.AdminAuditLogEnabled` OR `@Parameters.UnifiedAuditLogIngestionEnabled` is set to `False`.\n\n## Triage and response\n1. Determine if the user `{{@usr.email}}` intended to disable audit logging.\n2. If `{{@usr.email}}` is not responsible for disabling the audit logging, investigate `{{@usr.email}}` for anomalous activity. If necessary, initiate your company's incident response (IR) process."
  name               = "[TBOL] Microsoft 365 Audit Logging Disabled"

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
    name            = "unified_audit_disabled"
    query           = "source:microsoft-365 @evt.name:Set-AdminAuditLogConfig @Parameters.UnifiedAuditLogIngestionEnabled:False"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@usr.email"]
    name            = "admin_audit_disabled"
    query           = "source:microsoft-365 @evt.name:Set-AdminAuditLogConfig @Parameters.AdminAuditLogEnabled:False"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_upq-n7a-f4x" {
  case {
    condition = "forwarding_rule > 0"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a user sets up a mail forwarding rule to another email address. An adversary or insider threat could set a forwarding rule to forward all emails to an external email address.\n\n## Strategy\nMonitor Microsoft 365 audit logs to look for events with `@evt.name` value of `Set-Mailbox`, where a value is set for `@Parameters.ForwardingSmtpAddress` and the `@evt.outcome` is `True`.\n\n## Triage and response\n1. Inspect the `@Parameters.ForwardingSmtpAddress` for `{{@usr.email}}` to see if it is sending email to an external non-company owned domain.\n2. Determine if there is a legitimate use case for the mail forwarding rule.\n3. If `{{@usr.email}}` is not aware of the mail forwarding rule, investigate all `{{@usr.email}}` accounts for anomalous activity. "
  name               = "[TBOL] Exchange Online mail forwarding rule enabled"

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
    name            = "forwarding_rule"
    query           = "source:microsoft-365 @evt.name:Set-Mailbox -@Parameters.ForwardingSmtpAddress:\"\" @Parameters.ForwardingSmtpAddress:* @evt.outcome:True"
  }

  type = "log_detection"
}
resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_1tw-zmy-4nf" {
  case {
    condition = "member_assigned_built_in_administrator_role > 0"
    status    = "medium"
  }

  enabled            = "true"
  has_extended_title = "true"
  message            = "## Goal\nDetect an Azure Active Directory (Azure AD) member being added to a [built-in Administrative role][1].\n\n## Strategy\nMonitor Azure AD Audit logs for the following operations:\n\n* `@evt.name:\"Add member to role\"` \n* `@properties.targetResources.modifiedProperties.newValue:*Administrator*`\n\nAzure AD uses roles to assign privileges to users. There are over 80 roles available, the list below details some of the highest privileged roles that adversaries could target:\n\n* [Application Administrator][2]\n* [Cloud Application Administrator][3]\n* [Exchange Administrator][4]\n* [Privileged Role Administrator][5]\n* [User Administrator][6]\n* [Sharepoint Administrator][7]\n* [Hybrid Identity Administrator][8]\n\nThis [whitepaper][9] from Mandiant describes the abuse of Azure AD privileged roles.\n\n## Triage and response\n1. Determine if `{{@usr.id}}` should have made a `{{@evt.name}}` API call.\n2. If the API call was not made by the user:\n  * Rotate user credentials.\n  * Determine what other API calls were made by the user.\n  * Begin your organization's incident response (IR) process and investigate.\n3. If the API call was made legitimately by the user:\n  * Determine if `{{@usr.id}}` was authorized to make the change.\n  * Follow Microsoft's [best practices][10] where possible to ensure the user was assigned the correct level of privileges for their function.\n\n\n[1]: https://docs.microsoft.com/en-us/azure/active-directory/roles/permissions-reference\n[2]: https://docs.microsoft.com/en-us/azure/active-directory/roles/permissions-reference#application-administrator\n[3]: https://docs.microsoft.com/en-us/azure/active-directory/roles/permissions-reference#cloud-application-administrator\n[4]: https://docs.microsoft.com/en-us/azure/active-directory/roles/permissions-reference#exchange-administrator\n[5]: https://docs.microsoft.com/en-us/azure/active-directory/roles/permissions-reference#privileged-role-administrator\n[6]: https://docs.microsoft.com/en-us/azure/active-directory/roles/permissions-reference#user-administrator\n[7]: https://docs.microsoft.com/en-us/azure/active-directory/roles/permissions-reference#sharepoint-administrator\n[8]: https://docs.microsoft.com/en-us/azure/active-directory/roles/permissions-reference#hybrid-identity-administrator\n[9]: https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/wp-m-unc2452-2021-000343-01.pdf\n[10]: https://docs.microsoft.com/en-us/azure/active-directory/roles/best-practices"
  name               = "CLONED Azure AD member assigned built-in Administrator role"

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
    name            = "member_assigned_built_in_administrator_role"
    query           = "source:azure.activedirectory @properties.targetResources.modifiedProperties.newValue:*Administrator* @evt.category:AuditLogs @evt.name:\"Add member to role\" -@properties.targetResources.modifiedProperties.newValue:\"\\\"Global Administrator\\\"\" @evt.outcome:success"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_2j6-ul8-snc" {
  case {
    condition = "list_connectionstrings > 0"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a user successfully requests to view a CosmoDB connection string with the Azure API. An attacker with the appropriate privileges can view a connection string and use it to access or modify data in the CosmoDB database. \n\n## Strategy\nMonitor Azure CosmoDB logs where `@evt.name` is `\"MICROSOFT.DOCUMENTDB/DATABASEACCOUNTS/LISTCONNECTIONSTRINGS/ACTION\"` and `@evt.outcome` is `Success`.\n\n## Triage and response\n1. Verify that the user (`{{@usr.name}}`) should be viewing the connection string for the following CosmoDB database: ({{`@resourceId`}}).\n2. If the activity is not expected, investigate the activity around the CosmoDB ({{`@resourceId`}})."
  name               = "[TBOL] Azure user viewed CosmosDB connection string"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation = "count"
    name        = "list_connectionstrings"
    query       = "source:azure.documentdb @evt.name:\"MICROSOFT.DOCUMENTDB/DATABASEACCOUNTS/LISTCONNECTIONSTRINGS/ACTION\" @evt.outcome:Success"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_7bm-87b-dgp" {
  case {
    condition = "security_group_open_to_world > 0"
    status    = "high"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an Azure network security group allows inbound traffic from all IP Addresses.\n\n## Strategy\nThis rule monitors Azure Activity logs for network changes and detects when the `@evt.name` has a value of  `MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/WRITE`, `@properties.securityRules.properties.direction` has a value of `Inbound`, `@properties.securityRules.properties.access` has a value of `Allow`, and `@properties.securityRules.properties.sourceAddressPrefix` has a value of either `0.0.0.0/0` OR `*`.\n\n## Triage and response\n1. Inspect which Virtual Machines are associated with this security group.\n2. Determine whether this security group and the VMs should permit inbound traffic from all IP addresses.\n"
  name               = "[TBOL] Azure Network Security Group Open to the World"

  options {
    decrease_criticality_based_on_env = "true"
    detection_method                  = "threshold"
    evaluation_window                 = "900"
    keep_alive                        = "3600"
    max_signal_duration               = "86400"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@resourceId"]
    name            = "security_group_open_to_world"
    query           = "source:azure.network @evt.name:\"MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/WRITE\" @properties.securityRules.properties.direction:Inbound @properties.securityRules.properties.access:Allow @properties.securityRules.properties.sourceAddressPrefix:(\"0.0.0.0/0\" OR \"*\")"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_ajz-bjm-ram" {
  case {
    condition = "export_uri > 0"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect if an Azure snapshot is exported. Export URLs generated in Azure are accessible to anyone with the URL.\n\n## Strategy\nMonitor Azure logs where `@evt.name` is `\"MICROSOFT.COMPUTE/SNAPSHOTS/BEGINGETACCESS/ACTION\"` and `@evt.outcome` is `Success`.\n\n## Triage and response\n1. Verify the snapshot (`@resourceId`) has a legitimate reason for being exported.\n2. If the activity is not expected, investigate the activity around the IP (`{{@network.client.ip}}`) creating the export URL."
  name               = "[TBOL] Azure snapshot export URI created"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation = "count"
    name        = "export_uri"
    query       = "source:azure.compute @evt.name:\"MICROSOFT.COMPUTE/SNAPSHOTS/BEGINGETACCESS/ACTION\" @evt.outcome:Success"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_es2-oxu-a0t" {
  case {
    condition = "a > 0"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an Azure network security rule has been created, modified, or deleted.\n\n## Strategy\nMonitor Azure activity logs and detect when the `@evt.name` is equal to any of the following names:\n- `MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE` \n- `MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/DELETE`\n\nand `@evt.outcome` is equal to `Success`.\n\n## Triage and response\n1. Inspect the security rule and determine if it exposes any Azure resources that should not be made public.\n"
  name               = "[TBOL] Azure SQL Server Firewall Rules Created or Modified"

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
    query           = "source:azure.sql @evt.name:\"MICROSOFT.SQL/SERVERS/FIREWALLRULES/WRITE\" @evt.outcome:Success"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_ezj-tso-kis" {
  case {
    condition = "member_assigned_built_in_administrator_role > 0"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect an Azure Active Directory (Azure AD) member being added to a [built-in Administrative role][1].\n\n## Strategy\nMonitor Azure AD Audit logs for the following operations:\n\n* `@evt.name:\"Add member to role\"` \n* `@properties.targetResources.modifiedProperties.newValue:*Administrator*`\n\nAzure AD uses roles to assign privileges to users. There are over 80 roles available, the list below details some of the highest privileged roles that adversaries could target:\n\n* [Application Administrator][2]\n* [Cloud Application Administrator][3]\n* [Exchange Administrator][4]\n* [Privileged Role Administrator][5]\n* [User Administrator][6]\n* [Sharepoint Administrator][7]\n* [Hybrid Identity Administrator][8]\n\nThis [whitepaper][9] from Mandiant describes the abuse of Azure AD privileged roles.\n\n## Triage and response\n1. Determine if `{{@usr.id}}` should have made a `{{@evt.name}}` API call.\n2. If the API call was not made by the user:\n  * Rotate user credentials.\n  * Determine what other API calls were made by the user.\n  * Begin your organization's incident response (IR) process and investigate.\n3. If the API call was made legitimately by the user:\n  * Determine if `{{@usr.id}}` was authorized to make the change.\n  * Follow Microsoft's [best practices][10] where possible to ensure the user was assigned the correct level of privileges for their function.\n\n\n[1]: https://docs.microsoft.com/en-us/azure/active-directory/roles/permissions-reference\n[2]: https://docs.microsoft.com/en-us/azure/active-directory/roles/permissions-reference#application-administrator\n[3]: https://docs.microsoft.com/en-us/azure/active-directory/roles/permissions-reference#cloud-application-administrator\n[4]: https://docs.microsoft.com/en-us/azure/active-directory/roles/permissions-reference#exchange-administrator\n[5]: https://docs.microsoft.com/en-us/azure/active-directory/roles/permissions-reference#privileged-role-administrator\n[6]: https://docs.microsoft.com/en-us/azure/active-directory/roles/permissions-reference#user-administrator\n[7]: https://docs.microsoft.com/en-us/azure/active-directory/roles/permissions-reference#sharepoint-administrator\n[8]: https://docs.microsoft.com/en-us/azure/active-directory/roles/permissions-reference#hybrid-identity-administrator\n[9]: https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/wp-m-unc2452-2021-000343-01.pdf\n[10]: https://docs.microsoft.com/en-us/azure/active-directory/roles/best-practices"
  name               = "[TBOL] CLONED Azure AD member assigned built-in Administrator role"

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
    name            = "member_assigned_built_in_administrator_role"
    query           = "source:azure.activedirectory @properties.targetResources.modifiedProperties.newValue:*Administrator* @evt.category:AuditLogs @evt.name:\"Add member to role\" -@properties.targetResources.modifiedProperties.newValue:\"\\\"Global Administrator\\\"\" @evt.outcome:success"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_hi5-6w9-inn" {
  case {
    condition = "invite_external_user > 0"
    status    = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an invitation is sent to an external user.\n\n## Strategy\nMonitor Azure Active Directory Audit logs and detect when any `@evt.name` is equal to `Invite external user` and the `@evt.outcome` is equal to `success`.\n\n## Triage and response\n1. Review and determine if the invitation and its recipient are valid.\n"
  name               = "[TBOL] Azure user invited an external user"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@usr.id", "@properties.targetResources.userPrincipalName"]
    name            = "invite_external_user"
    query           = "source:azure.activedirectory @evt.name:\"Invite external user\" @evt.outcome:success"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_hiq-eju-wmx" {
  case {
    condition = "new_owner_sp > 0"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a new owner is added to a service principal, which applies to privilege escalation or persistence.\n\n## Strategy\nMonitor Azure Active Directory logs where `@evt.name` is `\"Add owner to service principal\"` and `@evt.outcome` of `Success`. \n\n## Triage and response\n1. Inspect that the user is added to a service principal in `@properties.targetResources`.\n2. Verify with the user (`{{@usr.name}}`) to determine if the owner addition is legitimate. "
  name               = "[TBOL] Azure new owner added for service principal"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation = "count"
    name        = "new_owner_sp"
    query       = "source:azure.activedirectory @evt.name:\"Add owner to service principal\" @evt.outcome:success @usr.name:*"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_hqk-f7e-h0i" {
  case {
    condition = "a > 0"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when the Datadog Azure function is deleted which will prevent Azure logs from being sent to Datadog.\n\n## Strategy\nMonitor Azure logs where `@evt.name` is `\"MICROSOFT.WEB/SITES/DELETE\"`, `@evt.outcome` is `Success`, and the `@resourceID` contains `DATADOG` and `LOG`. This rule does not work if the the Azure resource group or Azure function does not contain `DATADOG` or `LOG`.\n\n## Triage and response\n1. Verify the Azure function (`@resourceId`) is responsible for forwarding logs to Datadog.\n2. Determine if there is a legitimate reason for deleting the Azure function.\n3. If activity is not expected, investigate activity from the service principal (`@identity.authorization.evidence`) or user (`{{@usr.id}}`)."
  name               = "[TBOL] Azure Datadog Log Forwarder Deleted"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@resourceId"]
    query           = "source:azure.web @evt.name:\"MICROSOFT.WEB/SITES/DELETE\" @resourceId:(*DATADOG* AND *LOG*) @evt.outcome:Success"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_kh7-lj9-o7e" {
  case {
    condition = "waf_blocked_a_request > 0"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an Azure Frontdoor Web Application Firewall (WAF) blocks a request from an IP address.\n\n## Strategy\nThis rule monitors Azure Activity logs for Frontdoor Web Application Firewall logs and detects when the `@evt.name` has a value of  `Microsoft.Network/FrontDoor/WebApplicationFirewallLog/Write` and `@properties.action` has a value of `Block`.\n\n## Triage and response\n1. Inspect whether this request should have been blocked or not.\n2. Navigate to the IP dashboard and inspect other requests this IP address has made.\n"
  name               = "[TBOL] Azure Frontdoor WAF Blocked a Request"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "900"
    keep_alive                        = "3600"
    max_signal_duration               = "86400"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@properties.clientIP"]
    name            = "waf_blocked_a_request"
    query           = "source:azure.network @evt.name:\"Microsoft.Network/FrontDoor/WebApplicationFirewallLog/Write\" @properties.action:Block"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_kh8-9zh-pf0" {
  case {
    condition = "failed_login > 5 \u0026\u0026 successful_login > 0"
    name      = "Successful login"
    status    = "low"
  }

  case {
    condition = "failed_login > 5"
    name      = "Unsuccessful"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a user is a victim of an Account Take Over (ATO) by a brute force attack.\n\n## Strategy\nMonitor Azure Active Directory Sign-in logs and detect when any `@evt.category` is equal to  `SignInLogs`, and `@evt.outcome` is equal to `failure`.\n\n## Triage and response\n1. Inspect the log and determine if this was a valid login attempt.\n2. If the user was compromised, rotate user credentials.\n"
  name               = "[TBOL] Azure Portal brute force login"

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
    query           = "source:azure.activedirectory @evt.category:SignInLogs @evt.outcome:failure"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@usr.id"]
    name            = "successful_login"
    query           = "source:azure.activedirectory @evt.category:SignInLogs @evt.outcome:success"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_lx8-wvr-qlu" {
  case {
    condition = "new_owner > 0"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a user is added as a new owner for an Active Directory application which could be used as a persistence mechanism. \n\n## Strategy\nMonitor Azure Active Directory logs for `@evt.name: \"Add owner to application\"` has an `@evt.outcome` of `success`. \n\n## Triage and response\n1. Review evidence of anomalous activity for the user being added as an owner (`@properties.targetResources`) for the Active Directory application.\n2. Determine if there is a legitimate reason for the user being added to the application."
  name               = "[TBOL] Azure New Owner added to Azure Active Directory application"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation = "count"
    name        = "new_owner"
    query       = "source:azure.activedirectory @evt.name:\"Add owner to application\" @evt.outcome:success  @usr.name:* -@identity:*"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_lzo-pwv-lfa" {
  case {
    condition = "export_uri_generated > 0"
    status    = "high"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an Azure disk is successfully exported. Export URLs generated in Azure are accessible to anyone with the URI. This could be utilized as an exfiltration method that would allow an attacker to download an Azure Compute VM's disk as a VHD file.\n\n## Strategy\nMonitor Azure logs where `@evt.name` is `\"MICROSOFT.COMPUTE/SNAPSHOTS/DISKS/ACTION\"` and `@evt.outcome` is `Success`.\n\n## Triage and response\n1. Verify the disk (`{{@resourceId}}`) has a legitimate reason for being exported.\n2. If the activity is not expected, investigate the activity around the IP (`{{@network.client.ip}}`) creating the export URI."
  name               = "[TBOL] Azure disk export URI created"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@resourceId"]
    name            = "export_uri_generated"
    query           = "source:azure.compute @evt.name:\"MICROSOFT.COMPUTE/DISKS/BEGINGETACCESS/ACTION\" @evt.outcome:Success"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_m1z-s7e-e6o" {
  case {
    condition = "failed_login_multiple_user_accounts_same_ip_address > 10 \u0026\u0026 successful_login_same_ip_address > 0"
    name      = "Successful login after multiple failed login attempts from the same network IP address"
    status    = "high"
  }

  case {
    condition = "failed_login_multiple_user_accounts_same_ip_address > 10 "
    name      = "Multiple failed login attempts from the same network IP address"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\n\nDetect and identify the network IP address when multiple user accounts have login attempt activities recorded.\n\n## Strategy\n\nMonitor Azure Active Directory and detect when any `@evt.category` is equal to `SignInLogs` and more than 10 of the `@evt.outcome` are equal to `false` by the same network IP address.\n\nSecurity Signal returns **HIGH** if`@evt.outcome` has value of `success` after 10 multiple failed logins by the same network IP address.\n\n## Triage and response\n\n1. Inspect the log and determine if this was a valid login attempt.\n2. If the user was compromised, rotate user credentials.\n\n## Changelog\n14 June 2022 - Updated triggering cases to align with other credential stuffing rules. Also updated other backend options to reduce noise levels."
  name               = "[TBOL] Credential Stuffing Attack on Azure"

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
    name            = "failed_login_multiple_user_accounts_same_ip_address"
    query           = "source:azure.activedirectory @evt.category:SignInLogs @evt.outcome:failure"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@network.client.ip"]
    name            = "successful_login_same_ip_address"
    query           = "source:azure.activedirectory @evt.category:SignInLogs @evt.outcome:success"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_mk2-bur-49l" {
  case {
    condition = "member_assigned_global_administrator_role > 0"
    status    = "high"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect an Azure Active Directory (Azure AD) member being added to the [Global Administrator][1] role.\n\n## Strategy\nMonitor Azure AD Audit logs for the following operations:\n\n* `@evt.name:\"Add member to role\"` \n* `@properties.targetResources.modifiedProperties.newValue:\"\\\"Global Administrator\\\"\"`\n\nThe Global Administrator role can manage all aspects of Azure AD and Microsoft services that use Azure AD identities. An adversary can add users as Global Administrators in order to maintain access to Azure AD.\n\n## Triage and response\n1. Determine if `{{@usr.id}}` should have made a `{{@evt.name}}` API call.\n2. If the API call was not made by the user:\n  * Rotate user credentials.\n  * Determine what other API calls were made by the user.\n  * Begin your organization's incident response (IR) process and investigate.\n3. If the API call was made legitimately by the user:\n  * Determine if `{{@usr.id}}` was authorized to make the change.\n  * Follow Microsoft's [best practices][2] where possible to ensure the user was assigned the correct level of privileges for their function.\n\n\n[1]: https://docs.microsoft.com/en-us/azure/active-directory/roles/permissions-reference#global-administrator\n[2]: https://docs.microsoft.com/en-us/azure/active-directory/roles/best-practices"
  name               = "[TBOL] Azure AD member assigned Global Administrator role"

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
    name            = "member_assigned_global_administrator_role"
    query           = "source:azure.activedirectory @properties.targetResources.modifiedProperties.newValue:\"\\\"Global Administrator\\\"\" @evt.category:AuditLogs @evt.name:\"Add member to role\" @evt.outcome:success"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_psy-few-cla" {
  case {
    condition = "risk_level_aggregated_high > 0"
    name      = "High Risk Aggregated"
    status    = "high"
  }

  case {
    condition = "risk_level_during_signin_high > 0"
    name      = "High Risk During Sign-In"
    status    = "high"
  }

  case {
    condition = "risk_level_medium > 0"
    name      = "Medium Risk"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect whenever Azure Identity Protection categorizes an Azure Active Directory login as risky.\n\n## Strategy\nMonitor Azure Active Directory sign in activity (`@evt.name:\"Sign-in activity\"`) and generate a signal when Azure identifies the user as risky or compromised (`@properties.riskState:\"atRisk\" OR \"confirmedCompromised\"`). \n\n## Triage and response\n1. Analyze the location (`@network.client.geoip.subdivision.name`) of `{{@usr.id}}` to determine if they're logging into from their usual location. \n2. If log in activity is not legitimate, disable `{{@usr.id}}` account.\n3. Investigate any devices owned by `{{@usr.id}}`.\n\n## Changelog\n14 June 2022 - Fixed bug in rule query."
  name               = "[TBOL] Azure Active Directory Risky Sign-In"

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
    name            = "risk_level_during_signin_high"
    query           = "source:azure.activedirectory @evt.name:\"Sign-in activity\" @evt.category:SignInLogs -@evt.outcome:failure @properties.riskState:(atRisk OR confirmedCompromised) @properties.riskLevelDuringSignIn:high @properties.riskLevelDuringSignIn:(medium OR high)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@usr.id"]
    name            = "risk_level_aggregated_high"
    query           = "source:azure.activedirectory @evt.name:\"Sign-in activity\" @evt.category:SignInLogs -@evt.outcome:failure @properties.riskState:(atRisk OR confirmedCompromised) @properties.riskLevelAggregated:high @properties.riskLevelAggregated:(medium OR high)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@usr.id"]
    name            = "risk_level_medium"
    query           = "source:azure.activedirectory @evt.name:\"Sign-in activity\" @evt.category:SignInLogs -@evt.outcome:failure @properties.riskState:(atRisk OR confirmedCompromised) @properties.riskLevelAggregated:medium @properties.riskLevelDuringSignIn:medium"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_sgy-2aw-b1f" {
  case {
    condition = "a > 0"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an Azure network security group or an Azure network security rule has been created, modified, or deleted.\n\n## Strategy\nMonitor Azure activity logs and detect when the `@evt.name` is equal to any one of the following names:\n- `MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/WRITE`\n- `MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/DELETE`\n- `MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE` \n- `MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/DELETE`\n\nand `@evt.outcome` is equal to `Success`.\n\n## Triage and response\n1. Inspect the security group or security rule and determine if it exposes any Azure resources that should not be exposed.\n"
  name               = "[TBOL] Azure Network Security Groups or Rules Created, Modified, or Deleted"

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
    query           = "source:azure.network @evt.name:(\"MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/WRITE\" OR \"MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/SECURITYRULES/DELETE\" OR \"MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/DELETE\" OR \"MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/WRITE\") @evt.outcome:Success"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_ttm-b1d-tsx" {
  case {
    condition = "new_sp > 0"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\n\nDetect when a new service principal is created in Azure, which applies to a persistence mechanism.\n\n## Strategy\n\nMonitor Azure Active Directory logs where `@evt.name` is `\"Add service principal\"` and `@evt.outcome` of `Success`. \n\n## Triage and response\n\n1. Inspect the new service principal in `@properties.targetResources`.\n2. Verify with the user (`{{$usr.name}}`) to determine if the service principal is legitimate. "
  name               = "[TBOL] Azure New Service Principal created"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation = "count"
    name        = "new_sp"
    query       = "source:azure.activedirectory @evt.name:\"Add service principal\" @evt.outcome:success @usr.name:*"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_txd-gyx-va3" {
  case {
    condition = "list_keys > 0"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a user successfully requests to view a CosmoDB access key with the Azure API. An attacker with the appropriate privileges can view an access key and use it to access and manage the CosmoDB database. \n\n## Strategy\nMonitor Azure CosmoDB logs where `@evt.name` is `\"MICROSOFT.DOCUMENTDB/DATABASEACCOUNTS/LISTKEYS/ACTION\\\"` and `@evt.outcome` is `Success`.\n\n## Triage and response\n1. Verify that the user (`{{@usr.name}}`) should be viewing the access key for the following CosmoDB database: ({{`@resourceId`}}).\n2. If the activity is not expected, investigate the activity around the CosmoDB Database ({{`@resourceId`}})."
  name               = "[TBOL] Azure user viewed CosmosDB access keys"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation = "count"
    name        = "list_keys"
    query       = "source:azure.documentdb @evt.name:\"MICROSOFT.DOCUMENTDB/DATABASEACCOUNTS/LISTKEYS/ACTION\" @evt.outcome:Success"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_ubr-gto-qan" {
  case {
    condition = "waf_logged_a_request > 0"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an Azure Frontdoor Web Application Firewall (WAF) logs a request from an IP address.\n\n## Strategy\nThis rule monitors Azure Activity logs for Frontdoor Web Application Firewall logs and detects when the `@evt.name` has a value of  `Microsoft.Network/FrontDoor/WebApplicationFirewallLog/Write` and `@properties.action` has a value of `Log`.\n\n## Triage and response\n1. Inspect whether this request should have been blocked or not.\n2. Navigate to the IP dashboard and inspect other requests this IP address has made.\n"
  name               = "[TBOL] Azure Frontdoor WAF Logged a Request"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "900"
    keep_alive                        = "3600"
    max_signal_duration               = "86400"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@properties.clientIP"]
    name            = "waf_logged_a_request"
    query           = "source:azure.network @evt.name:\"Microsoft.Network/FrontDoor/WebApplicationFirewallLog/Write\" @properties.action:Log"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_utl-zi6-qio" {
  case {
    condition = "failed_login_mfa_denied_w_multiple_user_accounts > 10"
    name      = "Greater than 10 unique users"
    status    = "medium"
  }

  case {
    condition = "failed_login_mfa_denied_w_multiple_user_accounts > 3"
    name      = "Greater than 3 unique user"
    status    = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect and identify the network IP address when multiple user accounts failed to complete the MFA process.\n\n## Strategy\nMonitor Azure Active Directory Sign-in logs and detect when any `@evt.category` is equal to `SignInLogs`, `@properties.authenticationRequirement` is equal to `multiFactorAuthentication` and `@evt.outcome` is equal to `failure`.\n\n## Triage and response \n1. Inspect the log and determine if this was a valid login attempt.\n2. If the user was compromised, rotate user credentials.\n"
  name               = "[TBOL] Azure Login Explicitly Denied MFA"

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
    name            = "failed_login_mfa_denied_w_multiple_user_accounts"
    query           = "source:azure.activedirectory @evt.category:SignInLogs @properties.authenticationRequirement:multiFactorAuthentication @evt.outcome:failure"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_vqp-tci-jtu" {
  case {
    condition = "azure_firewall_threat_intel_alert > 0"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an Azure firewall threat intelligence alert is received.\n\n## Strategy\nMonitor Azure Network Diagnostic logs and detect when `@evt.name` is equal to `AzureFirewallThreatIntelLog`.\n\n## Triage and response\n1. Inspect the threat intelligence log.\n2. Investigate the activity from this IP address.\n"
  name               = "[TBOL] Azure Firewall Threat Intelligence Alert"

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
    name            = "azure_firewall_threat_intel_alert"
    query           = "source:azure.network @evt.name:AzureFirewallThreatIntelLog"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_w9h-xbi-yat" {
  case {
    condition = "member_assigned_built_in_administrator_role > 0"
    status    = "high"
  }

  enabled            = "true"
  has_extended_title = "true"
  message            = "## Goal\nDetect an Azure Active Directory (Azure AD) member being added to a [built-in Administrative role][1].\n\n## Strategy\nMonitor Azure AD Audit logs for the following operations:\n\n* `@evt.name:\"Add member to role\"` \n* `@properties.targetResources.modifiedProperties.newValue:*Administrator*`\n\nAzure AD uses roles to assign privileges to users. There are over 80 roles available, the list below details some of the highest privileged roles that adversaries could target:\n\n* [Application Administrator][2]\n* [Cloud Application Administrator][3]\n* [Exchange Administrator][4]\n* [Privileged Role Administrator][5]\n* [User Administrator][6]\n* [Sharepoint Administrator][7]\n* [Hybrid Identity Administrator][8]\n\nThis [whitepaper][9] from Mandiant describes the abuse of Azure AD privileged roles.\n\n## Triage and response\n1. Determine if `{{@usr.id}}` should have made a `{{@evt.name}}` API call.\n2. If the API call was not made by the user:\n  * Rotate user credentials.\n  * Determine what other API calls were made by the user.\n  * Begin your organization's incident response (IR) process and investigate.\n3. If the API call was made legitimately by the user:\n  * Determine if `{{@usr.id}}` was authorized to make the change.\n  * Follow Microsoft's [best practices][10] where possible to ensure the user was assigned the correct level of privileges for their function.\n\n\n[1]: https://docs.microsoft.com/en-us/azure/active-directory/roles/permissions-reference\n[2]: https://docs.microsoft.com/en-us/azure/active-directory/roles/permissions-reference#application-administrator\n[3]: https://docs.microsoft.com/en-us/azure/active-directory/roles/permissions-reference#cloud-application-administrator\n[4]: https://docs.microsoft.com/en-us/azure/active-directory/roles/permissions-reference#exchange-administrator\n[5]: https://docs.microsoft.com/en-us/azure/active-directory/roles/permissions-reference#privileged-role-administrator\n[6]: https://docs.microsoft.com/en-us/azure/active-directory/roles/permissions-reference#user-administrator\n[7]: https://docs.microsoft.com/en-us/azure/active-directory/roles/permissions-reference#sharepoint-administrator\n[8]: https://docs.microsoft.com/en-us/azure/active-directory/roles/permissions-reference#hybrid-identity-administrator\n[9]: https://www.fireeye.com/content/dam/fireeye-www/blog/pdfs/wp-m-unc2452-2021-000343-01.pdf\n[10]: https://docs.microsoft.com/en-us/azure/active-directory/roles/best-practices"
  name               = "[TBOL] Azure AD member assigned built-in Administrator role"

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
    name            = "member_assigned_built_in_administrator_role"
    query           = "source:azure.activedirectory @properties.targetResources.modifiedProperties.newValue:*Administrator* @evt.category:AuditLogs @evt.name:\"Add member to role\" -@properties.targetResources.modifiedProperties.newValue:\"\\\"Global Administrator\\\"\" @evt.outcome:success"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_wa7-pcs-eej" {
  case {
    condition = "vm_exec > 0"
    name      = "Virtual Machine"
    status    = "info"
  }

  case {
    condition = "scaleset_exec > 0"
    name      = "Virtual Machine Scale Set"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a user runs a command on an Azure Virtual Machine through the Azure CLI or Portal.\n\n## Strategy\nMonitor Azure Compute logs for `MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION` events that have `@evt.outcome` of `Success`. \n\n## Triage and response\n1. Reach out to the user to determine if the activity is legitimate. "
  name               = "[TBOL] User ran a command on Azure Compute"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation = "count"
    name        = "vm_exec"
    query       = "source:azure.compute @evt.name:\"MICROSOFT.COMPUTE/VIRTUALMACHINES/RUNCOMMAND/ACTION\" @evt.outcome:Success"
  }

  query {
    aggregation = "count"
    name        = "scaleset_exec"
    query       = "source:azure.compute @evt.name:\"MICROSOFT.COMPUTE/VIRTUALMACHINESCALESETS/VIRTUALMACHINES/RUNCOMMAND/ACTION\" @evt.outcome:Success"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_jqk-z1s-dra" {
  case {
    condition = "user_login_without_mfa > 0"
    status    = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when any user logs in to Azure AD without multi-factor authentication.\n\n## Strategy\nThis rule monitors Azure Activity logs for Active Directory logs and detects when any `@evt.category` has a value of  `SignInLogs`, and `@properties.authenticationRequirement` has a value of `singleFactorAuthentication`.\n\n## Triage and response\n1. Reach out to the user to determine if the login was legitimate.\n2. If the login was legitimate, request that the user enables 2FA.\n3. If the login wasn't legitimate, rotate the credentials.\n4. Review all user accounts to ensure MFA is enabled."
  name               = "[TBOL] Azure AD Login Without MFA"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "900"
    keep_alive                        = "3600"
    max_signal_duration               = "86400"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@usr.id"]
    name            = "user_login_without_mfa"
    query           = "source:azure.activedirectory @evt.category:SignInLogs @properties.authenticationRequirement:singleFactorAuthentication"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_jeu-yfb-r6a" {
  case {
    condition = "a > 0"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an Azure policy assignment has been created.\n\n## Strategy\nMonitor Azure activity logs and detect when the `@evt.name` is equal to `MICROSOFT.AUTHORIZATION/POLICYASSIGNMENTS/WRITE` and `@evt.outcome` is equal to `Success`.\n\n## Triage and response\n1. Inspect the policy assignment and determine if an unsolicited change was made on any Azure resources.\n"
  name               = "[TBOL] Azure Policy Assignment Created"

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
    query           = "source:azure @evt.name:\"MICROSOFT.AUTHORIZATION/POLICYASSIGNMENTS/WRITE\" @evt.outcome:Success"
  }

  type = "log_detection"
}

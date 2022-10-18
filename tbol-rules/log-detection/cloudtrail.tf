resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_jst-ln3-2fo" {
  case {
    condition = "a > 0"
    status    = "high"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect AWS root user activity. \n\n## Strategy\nMonitor CloudTrail and detect when any `@userIdentity.type` has a value of `Root`, but is not invoked by an AWS service or SAML provider.\n\n## Triage and response\n1. Reach out to the user to determine if the login was legitimate. \n2. If the login wasn't legitimate, rotate the credentials, enable 2FA, and open an investigation. \n\n* For best practices, check out the [AWS Root Account Best Practices][1] documentation.\n* For compliance, check out the [CIS AWS Foundations Benchmark controls][2] documentation.\n\n## Changelog\n30 March 2022 - Updated query and signal message.\n\n[1]: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html\n[2]: https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-cis-controls.html\n"
  name               = "[TBOL] AWS root account activity"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "900"
    keep_alive                        = "3600"
    max_signal_duration               = "86400"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.accountId"]
    query           = "source:cloudtrail @userIdentity.type:Root -@userIdentity.sessionContext.attributes.mfaAuthenticated:false -@userIdentity.invokedBy:* -@eventType:AwsServiceEvent -@additionalEventData.SamlProviderArn:*"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_k1c-kx8-tob" {
  case {
    status = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a user is enumerating API Gateway API keys.\n\n## Strategy\nBaseline `GetApiKeys` events by `@userIdentity.session_name` to surface anomalous `GetApiKeys` calls. \n\n## Triage and response\n1. Investigate activity for the following ARN `{{@userIdentity.arn}}` using `{{@userIdentity.session_name}}`.\n2. Review any other security signals for `{{@userIdentity.arn}}`.\n"
  name               = "[TBOL] Anomalous API Gateway API key reads by user"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "anomaly_detection"
    evaluation_window                 = "1800"
    keep_alive                        = "1800"
    max_signal_duration               = "1800"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.session_name"]
    query           = "source:cloudtrail @evt.name:GetApiKeys"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_klp-rxu-sjg" {
  case {
    status = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an AWS EKS node group makes a new API call.\n\n## Strategy\nThis rule sets a baseline for host activity across an AWS EKS node group, and enables detection of potentially anomalous activity when a node group makes a new API call.\n\nA new API call from a node group can indicate an attacker gaining a foothold within the system and trying API calls not normally associated with this node group.\n\n## Triage and response\n1. Investigate API activity for the AWS EKS node group to determine if the specific API call is malicious.\n2. Review any other security signals for the AWS EKS node group.\n3. If the activity is deemed malicious:\n    * If possible, isolate the compromised hosts.\n    * Determine what other API calls were made by the EKS node group.\n    * Begin your organization's incident response process and investigate."
  name               = "[TBOL] AWS EC2 new event for EKS Node Group"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "new_value"
    evaluation_window                 = "0"
    keep_alive                        = "3600"
    max_signal_duration               = "86400"

    new_value_options {
      forget_after       = "21"
      learning_duration  = "7"
      learning_method    = "duration"
      learning_threshold = "0"
    }
  }

  query {
    aggregation     = "new_value"
    group_by_fields = ["eks_nodegroup-name"]
    metric          = "@evt.name"
    metrics         = ["@evt.name"]
    query           = "source:cloudtrail"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_l3e-fe1-jjq" {
  case {
    condition = "public_poc > 0"
    name      = "Public POC"
    status    = "medium"
  }

  case {
    condition = "disable_cloudtrail_with_event_selectors > 0"
    name      = "IncludeManagementEvents set to False"
    status    = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when CloudTrail has been disabled by creating an event selector on the Trail.\n\n## Strategy\nThis rule lets you monitor CloudTrail and detect if an attacker used the [`PutEventSelectors`][1] API call to filter out management events, effectively disabling CloudTrail for the specified Trail.\n\nSee the [public Proof of Concept][2] (PoC) for this attack.\n\n## Triage and response\n1. Determine if `{{@userIdentity.arn}}` should have made the `{{@evt.name}}` API call.\n2. If the API call was **not** made legitimately by the user:\n  * Rotate user credentials.\n  * Determine what other API calls were made by the user.\n  * Remove the event selector using the `aws-cli` command [`put-event-selectors`][3] or use the [AWS console][4] to revert the event selector back to the last known good state.\n3. If the API call was made legitimately by the user:\n  * Determine if the user was authorized to make that change.\n  * If **Yes**, work with the user to ensure that CloudTrail logs for the affected account `{{@usr.account_id}}` are being sent to the Datadog platform.\n  * If **No**, remove the event selector using the `aws-cli` command [`put-event-selectors`][3] or reference the [AWS console documentation][4] to revert the event selector back to the last known good state.\n\n[1]: https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_PutEventSelectors.html\n[2]: https://github.com/RhinoSecurityLabs/Cloud-Security-Research/tree/master/AWS/cloudtrail_guardduty_bypass\n[3]: https://docs.aws.amazon.com/cli/latest/reference/cloudtrail/put-event-selectors.html\n[4]: https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-update-a-trail-console.html"
  name               = "[TBOL] AWS Disable Cloudtrail with event selectors"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "disable_cloudtrail_with_event_selectors"
    query           = "source:cloudtrail @eventSource:cloudtrail.amazonaws.com @evt.name:PutEventSelectors @requestParameters.eventSelectors.includeManagementEvents:false"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "public_poc"
    query           = "source:cloudtrail @eventSource:cloudtrail.amazonaws.com @evt.name:PutEventSelectors @requestParameters.eventSelectors.includeManagementEvents:false @responseElements.eventSelectors.dataResources.type:(\"AWS::S3::Object\" AND \"AWS::Lambda::Function\") @responseElements.eventSelectors.readWriteType:ReadOnly"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_l4i-pca-qc5" {
  case {
    condition = "unique_events_denied > 5"
    name      = "more than 5 APIs AccessDenied"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a user is assessing privileges in AWS through API bruteforcing technique.\n\n## Strategy\nThis rule lets you monitor CloudTrail to detect when the error message of `AccessDenied` is returned on more than 5 unique API calls.\n\n## Triage and response\n1. Determine if {{@userIdentity.arn}} should be attempting to use {{@evt.name}} API commands.\n   * Use the Cloud SIEM - User Investigation dashboard to assess user activity.\n2. Contact the user to see if they intended to make these API calls.\n3. If the user did not make the API calls:\n   * Rotate the credentials.\n   * Investigate to see what API calls might have been made that were successful throughout the rest of the environment.\n\n## Changelog\nRule updated on 3 March 2022."
  name               = "[TBOL] A user received multiple AccessDenied errors"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "900"
    keep_alive                        = "3600"
    max_signal_duration               = "86400"
  }

  query {
    aggregation     = "cardinality"
    distinct_fields = ["@evt.name"]
    group_by_fields = ["@userIdentity.arn"]
    name            = "unique_events_denied"
    query           = "source:cloudtrail @error.kind:AccessDenied"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_lip-jb0-whk" {
  case {
    status = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a user is attempting to retrieve a high number of secrets, through Cloudtrail's [`GetSecretValue`][1] event.\n\n## Strategy\nThis rule sets a baseline for user activity in the `GetSecretValue` event, and enables the detection of potentially anomalous activity when a user attempts to retrieve an anomalous volume of secrets.\n\nAn attacker may attempt to enumerate and access the AWS Secrets Manager to gain access to Application Programming Interface (API) keys, database credentials, Identity and Access Management (IAM) permissions, Secure Shell (SSH) keys, certificates, and more. Once these credentials are obtained, they can be used to perform lateral movement and access restricted information.\n\n## Triage and response\n1. Investigate API activity for `{{@userIdentity.session_name}}` to determine if the specific set of API calls are malicious.\n    * Use the investigation queries on the suggested actions panel.\n2. Review any other security signals for `{{@userIdentity.session_name}}`.\n3. If the activity is deemed malicious:\n    * Rotate user credentials.\n    * Determine what other API calls were made by the user.\n    * Rotate any AWS secrets that were accessed by the user with the `aws-cli` command [`update-secret`][2] or use the [AWS Console][3].\n    * Begin your organization's incident response process and investigate.\n4. If the activity is benign:\n    * Use the linked blog post in the suggested actions panel to tune out noise.\n\n[1]: https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_GetSecretValue.html\n[2]: https://docs.aws.amazon.com/cli/latest/reference/secretsmanager/update-secret.html\n[3]: https://docs.aws.amazon.com/secretsmanager/latest/userguide/manage_update-secret.html"
  name               = "[TBOL] User enumerated AWS Secrets Manager - Anomaly"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "anomaly_detection"
    evaluation_window                 = "1800"
    keep_alive                        = "1800"
    max_signal_duration               = "1800"
  }

  query {
    aggregation     = "cardinality"
    distinct_fields = ["@requestParameters.secretId"]
    group_by_fields = ["@userIdentity.arn"]
    query           = "source:cloudtrail @evt.name:GetSecretValue -@userIdentity.invokedBy:(apidestinations.events.amazonaws.com OR rds.amazonaws.com OR access-analyzer.amazonaws.com OR config.amazonaws.com)"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_liu-duw-ktn" {
  case {
    condition = "failed_login > 5 \u0026\u0026 successful_login_without_mfa > 0"
    name      = "Successful - MFA Unused"
    status    = "medium"
  }

  case {
    condition = "failed_login > 5 \u0026\u0026 successful_login_with_mfa > 0"
    name      = "Successful Login - MFA Used"
    status    = "info"
  }

  case {
    condition = "failed_login > 5"
    name      = "Failed Login"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a user is a victim of an Account Take Over (ATO) by a brute force attack.\n\n## Strategy\n This rule monitors CloudTrail and detects when any `@evt.name` has a value of `Console Login`, and `@responseElements.ConsoleLogin` has a value of `Failure`.\n\n## Triage and response\n1. Determine if the user logged in with 2FA.\n2. Reach out to the user and ensure the login was legitimate.\n\n## Changelog \n17 March 2022 - Update rule query."
  name               = "[TBOL] Potential brute force attack on AWS ConsoleLogin"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "900"
    keep_alive                        = "3600"
    max_signal_duration               = "86400"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "failed_login"
    query           = "source:cloudtrail @evt.name:ConsoleLogin @responseElements.ConsoleLogin:Failure"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "successful_login_without_mfa"
    query           = "source:cloudtrail @evt.name:ConsoleLogin @responseElements.ConsoleLogin:Success @userIdentity.sessionContext.attributes.mfaAuthenticated:false"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "successful_login_with_mfa"
    query           = "source:cloudtrail @evt.name:ConsoleLogin @responseElements.ConsoleLogin:Success @userIdentity.sessionContext.attributes.mfaAuthenticated:true"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_lri-zxh-zzt" {
  case {
    condition = "user_login_without_mfa > 0"
    name      = "user console login no mfa"
    status    = "medium"
  }

  case {
    condition = "root_login_without_mfa > 0"
    name      = "root console login no mfa"
    status    = "high"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when any user logs in to your AWS console without multi-factor authentication.\n\n## Strategy\nThis rule monitors CloudTrail and detects when any `IAMUser` or `Root` user does a `Console Login`, and `@userIdentity.sessionContext.attributes.mfaAuthenticated` has a value of `false`. \n\n**Notes:** \n\n- This rule triggers with a `High` severity if the user logging in is a `Root` user.\n- This rule ignores logins using SAML because 2FA is implemented on the IdP and not through AWS.\n\n## Triage and response\n1. Reach out to the {{@usr.name}} to determine if the login was legitimate. \n   * Use Cloud SIEM - User Investigation dashboard to see if the user: {{@usr.name}} with an account type of: {{@userIdentity.type}} has done any actions after logging in. \n2. If the login was legitimate, request that the user enables 2FA. \n3. If the login wasn't legitimate, rotate the credentials, enable 2FA and triage an actions uncovered from step 1.\n4. Review all user accounts to ensure MFA is enabled.\n\n## Changelog\n3 March 2022 - Rule updated\n"
  name               = "[TBOL] AWS Console login without MFA"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "900"
    keep_alive                        = "3600"
    max_signal_duration               = "86400"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.accountId", "@usr.name"]
    name            = "user_login_without_mfa"
    query           = "source:cloudtrail @evt.name:ConsoleLogin -@additionalEventData.MFAUsed:Yes @responseElements.ConsoleLogin:Success @userIdentity.type:IAMUser -@additionalEventData.SamlProviderArn:*"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.accountId", "@usr.name"]
    name            = "root_login_without_mfa"
    query           = "source:cloudtrail @evt.name:ConsoleLogin -@additionalEventData.MFAUsed:Yes @responseElements.ConsoleLogin:Success @userIdentity.type:Root -@additionalEventData.SamlProviderArn:*"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_o24-gns-6ex" {
  case {
    condition = "configuration_modified > 0"
    status    = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an attacker is trying to evade defenses by modifying CloudTrail.\n\n## Strategy\nThis rule detects if a user is modifying CloudTrail by monitoring the CloudTrail API using [UpdateTrail][1] API calls.\n\n## Triage and response\n1. Review the `@responseElements` in the `UpdateTrail` event to determine the scope of the changes.\n2. Determine if the user ARN (`{{@userIdentity.arn}}`) intended to make a CloudTrail modification.\n3. If the user did not make the API call:\n * Rotate the credentials.\n * Investigate if the same credentials made other unauthorized API calls.\n\n[1]: https://docs.aws.amazon.com/awscloudtrail/latest/APIReference/API_UpdateTrail.html"
  name               = "[TBOL] AWS CloudTrail configuration modified"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "configuration_modified"
    query           = "source:cloudtrail @evt.name:UpdateTrail"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_jkj-n2w-fkz" {
  case {
    status = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an attacker is attempting to hijack an EC2 AutoScaling Group.\n\n## Strategy\nThis rule lets you monitor AWS EC2 Autoscaling logs (`@eventSource:autoscaling.amazonaws.com`) to detect when an Autoscaling group receives an anomalous amount of API calls (`{{@evt.name}}`).\n\n## Triage and response\n1. Confirm if the user `{{@userIdentity.arn}}` intended to make the `{{@evt.name}}` API calls.\n2. If the user did not make the API calls:\n    * Rotate the credentials.\n    * Investigate if the same credentials made other unauthorized API calls."
  name               = "[TBOL] Anomalous amount of Autoscaling Group events"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "anomaly_detection"
    evaluation_window                 = "1800"
    keep_alive                        = "7200"
    max_signal_duration               = "86400"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@evt.name"]
    query           = "source:cloudtrail @eventSource:autoscaling.amazonaws.com"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_jgj-kcq-y5v" {
  case {
    name   = "s3_write_events"
    status = "high"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an AWS user performs S3 bucket write activities they do not usually perform. \n\n## Strategy\nMonitor cloudtrail logs for S3 Data Plane events (`@eventCategory:Data`) to detect when an AWS User (`@userIdentity.arn`) is detected performing anomalous S3 Write `(@evt.name:(Abort* OR Create* OR Delete* OR Initiate* OR Put* OR Replicate* OR Update*))` API calls. \n\n## Triage and response\n1. Determine if user: `{{@userIdentity.arn}}` should be performing the: `{{@evt.name}}` API calls.\n   * Use the Cloud SIEM - User Investigation dashboard to assess user activity.\n2. If not, investigate the user: `{{@userIdentity.arn}}` for indicators of account compromise and rotate credentials as necessary.\n"
  name               = "[TBOL] Anomalous S3 bucket activity from user ARN"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "anomaly_detection"
    evaluation_window                 = "1800"
    keep_alive                        = "7200"
    max_signal_duration               = "86400"
  }

  query {
    aggregation     = "cardinality"
    distinct_fields = ["@requestParameters.bucketName"]
    group_by_fields = ["@userIdentity.arn"]
    name            = "s3_write_events"
    query           = "source:cloudtrail @eventCategory:Data @eventSource:s3.amazonaws.com @evt.name:(Abort* OR Create* OR Delete* OR Initiate* OR Put* OR Replicate* OR Update*)"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_jet-3yn-fug" {
  case {
    condition = "a > 0"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a user deletes a publishing destination for a detector which will prevent the exporting of findings. \n\n## Strategy\nThis rule lets you monitor this CloudTrail API call to detect if a user has deleted a Guard Duty publishing destination.\n\n* [DeletePublishingDestination][1]\n\n## Triage and response\n1. Determine which user in your organization owns the API key that made this API call.\n2. Contact the user to see if they intended to make this API call.\n3. If the user did not make the API call:\n * Rotate the credentials.\n * Investigate if the same credentials made other unauthorized API calls.\n\n[1]: https://docs.aws.amazon.com/fr_fr/guardduty/latest/APIReference/API_DeletePublishingDestination.html"
  name               = "[TBOL] AWS GuardDuty publishing destination deleted"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    query           = "source:cloudtrail @evt.name:DeletePublishingDestination"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_iju-nhs-izn" {
  case {
    status = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an EC2 instance is assessing privileges in AWS through various enumeration and discovery techniques.\n\n## Strategy\nMonitor CloudTrail logs to identify when an EC2 instance (`@userIdentity.session_name:i-*\"`) generates an anomalous amount of `AccessDenied` events.\n\n## Triage and response\n1. Determine what events the EC2 instance `{{@userIdentity.session_name}}` are generating in the time frame of the signal.\n2. If the root cause is not a misconfiguration, investigate any other signals around the same time of the signal by looking at the Host Investigation dashboard."
  name               = "[TBOL] Anomalous amount of access denied events for AWS EC2 Instance"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "anomaly_detection"
    evaluation_window                 = "1800"
    keep_alive                        = "7200"
    max_signal_duration               = "86400"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.assumed_role"]
    query           = "source:cloudtrail @error.kind:AccessDenied @userIdentity.session_name:i-*"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_ihb-ufy-0nh" {
  case {
    status = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when the `AdministratorAccess` policy is attached to an AWS IAM user.\n\n## Strategy\nThis rule allows you to monitor CloudTrail and detect if an attacker has attached the AWS managed policy [`AdministratorAccess`][1] to an AWS IAM user using the [`AttachUserPolicy`][2] API call.\n\n## Triage and response\n1. Determine if `{{@userIdentity.session_name}}` should have made a `{{@evt.name}}` API call.\n2. If the API call was not made by the user:\n  * Rotate user credentials.\n  * Determine what other API calls were made by the user.\n  * Remove the `AdministratorAccess` policy from the `{{@requestParameters.userName}}` user using the `aws-cli` command [detach-user-policy][3].\n3. If the API call was made legitimately by the user:\n  * Determine if the user `{{@requestParameters.userName}}` requires the AdministratorAccess policy to perform the intended function.\n  * Advise the user to find the [least privileged][4] policy that allows the user to operate as intended.\n\n[1]: https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_job-functions.html#jf_administrator\n[2]: https://docs.aws.amazon.com/IAM/latest/APIReference/API_AttachUserPolicy.html\n[3]: https://docs.aws.amazon.com/cli/latest/reference/iam/detach-user-policy.html\n[4]: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege"
  name               = "[TBOL] AWS IAM privileged policy was applied to a user"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "new_value"
    evaluation_window                 = "0"
    keep_alive                        = "1800"
    max_signal_duration               = "1800"

    new_value_options {
      forget_after       = "7"
      learning_duration  = "1"
      learning_method    = "duration"
      learning_threshold = "0"
    }
  }

  query {
    aggregation     = "new_value"
    group_by_fields = ["@userIdentity.arn"]
    metric          = "@requestParameters.userName"
    metrics         = ["@requestParameters.userName"]
    query           = "source:cloudtrail @eventSource:iam.amazonaws.com @evt.name:AttachUserPolicy @requestParameters.policyArn:\"arn:aws:iam::aws:policy/AdministratorAccess\""
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_qc2-ef2-n3h" {
  case {
    condition = "cloudwatch_disable_or_delete_rule > 0"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a CloudWatch rule has been disabled or deleted.\n\n## Strategy\nThis rule lets you monitor CloudTrail and detect if a [`DisableRule`][1] or [`DeleteRule`][2] API call has occurred. An attacker may delete rules in an attempt to evade defenses.\n\n## Triage and response\n1. Determine if `{{@userIdentity.arn}}` should have made the `{{@evt.name}}` API call.\n2. If the API call was **not** made legitimately by the user:\n  * Rotate user credentials.\n  * Determine what other API calls were made by the user.\n  * Enable or create a rule using the `aws-cli` commands [`enable-rule`][4] or [`put-rule`][3], or reference the [AWS documentation][5] to revert the rules back to the last known good state.\n3. If the API call was made legitimately by the user:\n  * Determine if the user was authorized to make that change.\n  * If **Yes**, consider including the EventBus name in a [suppression list][6]: `{{@requestParameters.eventBusName}}`.\n  * If **No**, enable or create a rule using the `aws-cli` commands [`enable-rule`][4] or [`put-rule`][3], respectively, or reference the [AWS documentation][5] to revert the rules back to the last known good state.\n    * Begin your company's IR process and investigate.\n\n[1]: https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_DeleteRule.html\n[2]: https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_DisableRule.html\n[3]: https://docs.aws.amazon.com/cli/latest/reference/events/put-rule.html\n[4]: https://docs.aws.amazon.com/cli/latest/reference/events/enable-rule.html\n[5]: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-rules.html\n[6]: https://www.datadoghq.com/blog/writing-datadog-security-detection-rules/#customize-security-signal-messages-to-fit-your-environment"
  name               = "[TBOL] AWS CloudWatch rule disabled or deleted"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "cloudwatch_disable_or_delete_rule"
    query           = "source:cloudtrail @eventSource:events.amazonaws.com @evt.name:(DisableRule OR DeleteRule) -@userIdentity.invokedBy:(backup.amazonaws.com OR schemas.amazonaws.com OR cloudformation.amazonaws.com)"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_qk2-i8q-n2e" {
  case {
    status = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when the `AdministratorAccess` policy is attached to an AWS IAM role.\n\n## Strategy\nThis rule lets you monitor CloudTrail to detect if an attacker has attached the AWS managed policy [`AdministratorAccess`][1] to a new AWS IAM role via the [`AttachRolePolicy`][2] API call.\n\n## Triage and response\n1. Determine if `{{@userIdentity.session_name}}` should have made a `{{@evt.name}}` API call.\n2. If the API call was not made by the user:\n  * Rotate user credentials.\n  * Determine what other API calls were made by the user.\n  * Remove the `AdministratorAccess` policy from the `{{@requestParameters.roleName}}` role using the `aws-cli` command [detach-role-policy][3].\n3. If the API call was made legitimately by the user:\n  * Determine if the role `{{@requestParameters.roleName}}` requires the AdministratorAccess policy to perform its intended function.\n  * Advise the user to find the [least privileged][4] policy that allows the role to operate as intended.\n\n[1]: https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_job-functions.html#jf_administrator\n[2]: https://docs.aws.amazon.com/IAM/latest/APIReference/API_AttachRolePolicy.html\n[3]: https://docs.aws.amazon.com/cli/latest/reference/iam/detach-role-policy.html\n[4]: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege"
  name               = "[TBOL] AWS IAM privileged policy was applied to a role"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "new_value"
    evaluation_window                 = "0"
    keep_alive                        = "1800"
    max_signal_duration               = "1800"

    new_value_options {
      forget_after       = "7"
      learning_duration  = "1"
      learning_method    = "duration"
      learning_threshold = "0"
    }
  }

  query {
    aggregation     = "new_value"
    group_by_fields = ["@userIdentity.arn"]
    metric          = "@requestParameters.roleName"
    metrics         = ["@requestParameters.roleName"]
    query           = "source:cloudtrail @eventSource:iam.amazonaws.com @evt.name:AttachRolePolicy @requestParameters.policyArn:\"arn:aws:iam::aws:policy/AdministratorAccess\" -@userIdentity.invokedBy:sso.amazonaws.com -@http.useragent:sso.amazonaws.com"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_qrt-5xy-oln" {
  case {
    status = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a user is attempting to retrieve a high number of parameters, through Cloudtrail's [`GetParameter`][1] event.\n\n## Strategy\nThis rule sets a baseline for user activity in the `GetParameter` event, and enables detection of potentially anomalous activity when a user attempts to retrieve an anomalous volume of parameters.\n\nAn attacker may attempt to enumerate and access the AWS Systems Manager to gain access to Application Programming Interface (API) keys, database credentials, Identity and Access Management (IAM) permissions, Secure Shell (SSH) keys, certificates, and more. Once these credentials are obtained, they can be used to perform lateral movement and access restricted information.\n\n## Triage and response\n1. Investigate API activity for `{{@userIdentity.session_name}}` to determine if the specific set of API calls are malicious.\n    * Use the investigation queries on the suggested actions panel.\n2. Review any other security signals for `{{@userIdentity.session_name}}`.\n3. If the activity is deemed malicious:\n    * Rotate user credentials.\n    * Determine what other API calls were made by the user.\n    * Rotate any parameters that were accessed by the user with the `aws-cli` command [`put-parameter`][2].\n    * Begin your organization's incident response process and investigate.\n4. If the activity is benign:\n    * Use the linked blog post in the suggested actions panel to tune out noise.\n\n[1]: https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_GetParameter.html\n[2]: https://docs.aws.amazon.com/cli/latest/reference/ssm/put-parameter.html"
  name               = "[TBOL] User enumerated AWS Systems Manager parameters - Anomaly"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "anomaly_detection"
    evaluation_window                 = "1800"
    keep_alive                        = "1800"
    max_signal_duration               = "1800"
  }

  query {
    aggregation     = "cardinality"
    distinct_fields = ["@requestParameters.name"]
    group_by_fields = ["@userIdentity.arn"]
    query           = "source:cloudtrail @eventSource:ssm.amazonaws.com @evt.name:GetParameter -@userIdentity.invokedBy:(apidestinations.events.amazonaws.com OR rds.amazonaws.com OR access-analyzer.amazonaws.com OR config.amazonaws.com)"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_qut-aoc-qxi" {
  case {
    condition = "a > 0"
    status    = "high"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an attacker is trying to evade defenses by deleting a GuardDuty detector.\n\n## Strategy\nThis rule lets you monitor this CloudTrail API call to detect if an attacker is deleting a GuardDuty Detector:\n\n* [DeleteDetector][1]\n\n## Triage and response\n1. Determine which user in your organization owns the API key that made this API call.\n2. Contact the user to see if they intended to make this API call.\n3. If the user did not make the API call:\n * Rotate the credentials.\n * Investigate if the same credentials made other unauthorized API calls.\n\n[1]: https://docs.aws.amazon.com/guardduty/latest/ug/delete-detector.html\n"
  name               = "[TBOL] AWS GuardDuty detector deleted"

  options {
    decrease_criticality_based_on_env = "true"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    query           = "source:cloudtrail @evt.name:DeleteDetector"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_sql-qfr-jxl" {
  case {
    condition = "firehose_destination_modified > 0"
    name      = "firehose_destination_modified"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetects when an AWS Kinesis Firehose Destination is modified.\n\n## Strategy\nThe rule monitors AWS Kinesis Firehose logs `@eventSource:firehose.amazonaws.com` and detects when the `@evt.name` is `UpdateDestination`.  \n\n## Triage and response\n1. Determine if {{@userIdentity.arn}} is expected to perform the {{@evt.name}} API call on the account: {{@usr.account_id}}.\n2. If the API call was not made by the user, rotate the user credentials and investigate what other APIs were successfully accessed.\n   * Rotate the credentials.\n   * Investigate if the same credentials made other unauthorized API calls."
  name               = "[TBOL] AWS Kinesis Firehose stream destination modified"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "7200"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@requestParameters.deliveryStreamName"]
    name            = "firehose_destination_modified"
    query           = "source:cloudtrail @eventSource:firehose.amazonaws.com @evt.name:UpdateDestination -@http.useragent:(cloudformation.amazonaws.com OR APN\\/*)"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_ifc-n3z-3gn" {
  case {
    condition = "snapshot_created > 0 \u0026\u0026 snapshot_shared > 0"
    name      = "EBS Snapshot created then shared"
    status    = "high"
  }

  case {
    condition = "snapshot_shared > 0"
    name      = "EBS Snapshot shared"
    status    = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect the possible exfiltration of an EBS snapshot.\n\n## Strategy\nThis rule allows you to monitor CloudTrail and detect the following API calls within a 15 minute time window:\n\n* [`CreateSnapshot`][1]\n* [`ModifySnapshotAttribute`][2]\n\nAn attacker can create a EBS snapshot from the EBS volume and modify the permissions of the snapshot to allow it to be shared [publicly][3] or with another AWS account. Using an attacker-controlled account, a new EBS volume can be created from the snapshot and attached to an EC2 instance for analysis.\n\n## Triage and response\n1. Determine if `{{@userIdentity.arn}}` should have made the API calls.\n2. If the API call was not made by the user:\n  * Rotate user credentials.\n  * Determine what other API calls were made by the user.\n  * Remove any snapshot attributes generated by the user with the `aws-cli` command [`modify-snapshot-attribute`][4].\n  * Begin your organization's incident response process and investigate.\n3. If the API calls were made by the user:\n  * Determine if the user should be performing these API calls.\n  * If **No**, see if other API calls were made by the user and determine if they warrant further investigation.\n\n[1]: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateSnapshot.html\n[2]: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ModifySnapshotAttribute.html\n[3]: https://docs.datadoghq.com/security_platform/default_rules/cloudtrail-aws-ebs-snapshot-made-public/\n[4]: https://docs.aws.amazon.com/cli/latest/reference/ec2/modify-snapshot-attribute.html"
  name               = "[TBOL] AWS EBS Snapshot possible exfiltration"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "7200"
    keep_alive                        = "7200"
    max_signal_duration               = "7200"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@responseElements.snapshotId"]
    name            = "snapshot_created"
    query           = "source:cloudtrail @evt.name:CreateSnapshot -@userIdentity.invokedBy:(dlm.amazonaws.com OR events.amazonaws.com OR backup.amazonaws.com)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@requestParameters.snapshotId"]
    name            = "snapshot_shared"
    query           = "source:cloudtrail @evt.name:ModifySnapshotAttribute @requestParameters.attributeType:CREATE_VOLUME_PERMISSION -@userIdentity.invokedBy:(dlm.amazonaws.com OR events.amazonaws.com OR backup.amazonaws.com)"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_iay-ro4-rls" {
  case {
    condition = "route_created > 0"
    name      = "VPC route table created"
    status    = "info"
  }

  case {
    condition = "route_modified > 0"
    name      = "VPC route table modified"
    status    = "info"
  }

  case {
    condition = "route_deleted > 0"
    name      = "VPC route table deleted"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an AWS Route Table has been created or modified.\n\n## Strategy\nThis rule lets you monitor CloudTrail and detect when an AWS Route Table has been created or modified with one of the following API calls:\n* [CreateRoute][1] \n* [CreateRouteTable][2] \n* [ReplaceRoute][3] \n* [ReplaceRouteTableAssociation][4] \n* [DeleteRouteTable][5] \n* [DeleteRoute][6] \n* [DisassociateRouteTable][7]\n\n## Triage and response\n1. Determine if {{@userIdentity.arn}} is expected to perform the {{@evt.name}} API call.\n2. Contact the principal owner and see if this was an API call which was made by the user.\n3. If the API call was not made by the user, rotate the user credentials and investigate what other APIs were successfully accessed.\n\n## Changelog\n6 April 2022 - Update signal message. Updated rule query/case layout\n\n[1]: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateRoute.html \n[2]: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateRouteTable \n [3]: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ReplaceRoute.html \n [4]: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ReplaceRouteTableAssociation \n [5]: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DeleteRouteTable.html \n [6]: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DeleteRoute.html \n [7]: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DisassociateRouteTable.html\n"
  name               = "[TBOL] AWS Route Table created or modified"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "43200"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "route_created"
    query           = "source:cloudtrail @evt.name:(CreateRoute OR CreateRouteTable)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "route_modified"
    query           = "source:cloudtrail @evt.name:(ReplaceRoute OR ReplaceRouteTableAssociation OR DisassociateRouteTable)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "route_deleted"
    query           = "source:cloudtrail @evt.name:(DeleteRouteTable OR DeleteRoute)"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_tfo-4ok-voc" {
  case {
    condition = "a > 0"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an attacker is destroying an EC2 subnet.\n\n## Strategy\nThis rule lets you monitor this CloudTrail API call to detect if an attacker is deleting an EC2 subnet.\n\n* [DeleteSubnet][1]\n\n## Triage and response\n1. Determine if {{@userIdentity.arn}} should be deleting EC2 subnets.\n2. Contact the user to see if they intended to make this API call.\n3. If the user did not make the API call:\n   * Rotate the credentials.\n   * Investigate if the same credentials made other unauthorized API calls.\n\n## Changelog\n1 April 2022 - Update rule and signal message\n\n[1]: https://docs.aws.amazon.com/cli/latest/reference/ec2/delete-subnet.html\n"
  name               = "[TBOL] AWS EC2 subnet deleted"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    query           = "source:cloudtrail @eventSource:ec2.amazonaws.com @evt.name:DeleteSubnet -@level:Error"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_tjc-mgi-jcu" {
  case {
    status = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "\n## Goal\nDetect an Impossible Travel event when a `@userIdentity.type:` `{{@userIdentity.type}}` uses an AWS EC2 access key and filter out VPNs and AWS Internal IPs.\n\n## Strategy\nThe Impossible Travel detection type's algorithm compares the GeoIP data of the last log and the current log to determine if the EC2 instance with `@userIdentity.session_name:` `{{@userIdentity.session_name}}`  traveled more than 500km at over 1,000km/hr and used an AWS EC2 access key.\n\n## Triage and response\n1. Determine if the `@userIdentity.accessKeyId:` `{{@userIdentity.accessKeyId}}` for `@userIdentity.session_name:` `{{@userIdentity.session_name}}` instance should be used from `{{@impossible_travel.triggering_locations.first_location.city}}, {{@impossible_travel.triggering_locations.first_location.country}}` and `{{@impossible_travel.triggering_locations.second_location.city}}, {{@impossible_travel.triggering_locations.second_location.country}}`.\n2. If the EC2 access key should not be used from `{{@impossible_travel.triggering_locations.first_location.city}}, {{@impossible_travel.triggering_locations.first_location.country}}` and `{{@impossible_travel.triggering_locations.second_location.city}}, {{@impossible_travel.triggering_locations.second_location.country}}`., then consider isolating the account and reset credentials.\n3. Audit any instance actions that may have occurred after the illegitimate login.\n\n**NOTE** VPNs and other anonymous IPs are filtered out of this signal\n\n## Changelog\n7 April 2022 - Updated rule name and signal message."
  name               = "[TBOL] Compromised AWS EC2 Instance"

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
    group_by_fields = ["@userIdentity.accessKeyId"]
    metric          = "@network.client.geoip"
    metrics         = ["@network.client.geoip"]
    query           = "source:cloudtrail -@level:Error @userIdentity.type:AssumedRole @userIdentity.session_name:i-* -@network.client.geoip.invalidAddress:\"AWS Internal\" -@threat_intel.results.category:anonymizer"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_tmq-os5-tjy" {
  case {
    status = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a user has attempted to assume an anomalous number of unique roles.\n\n## Strategy\nThis rule sets a baseline for user activity for the [`AssumeRole`][1] API call, and enables detection of potentially anomalous activity.\n\nAn attacker may attempt this for the following reasons:\n\n* To identify which roles the user account has access to.\n* To identify what AWS services are being used internally.\n* To identify third party integrations and internal software.\n\n## Triage and response\n1. Investigate activity for the following ARN `{{@userIdentity.arn}}` using `{{@userIdentity.session_name}}`.\n2. Review any other security signals for `{{@userIdentity.arn}}`.\n3. If the activity is deemed malicious:\n    * Rotate user credentials.\n    * Determine what other API calls were made by the user.\n    * Begin your organization's incident response process and investigate.\n\n[1]: https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html"
  name               = "[TBOL] Anomalous number of assumed roles from user"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "anomaly_detection"
    evaluation_window                 = "1800"
    keep_alive                        = "7200"
    max_signal_duration               = "86400"
  }

  query {
    aggregation     = "cardinality"
    distinct_fields = ["@requestParameters.roleArn"]
    group_by_fields = ["@usr.name"]
    query           = "source:cloudtrail @userIdentity.type:IAMUser @evt.name:AssumeRole"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_tta-j63-a9x" {
  case {
    condition = "a > 0"
    status    = "high"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a user deletes an Amazon Detective behavior graph.\n\n## Strategy\nThis rule lets you monitor this CloudTrail API call to detect if a user has deleted an Amazon Detective behavior graph:\n\n* [DeleteGraph][1]\n\n## Triage and response\n1. Determine if the behavior graph should have been deleted.\n2. Determine which user ({{@userIdentity.arn}}) in your organization deleted the behavior graph.\n3. If the user did not make the API call:\n   * Rotate the credentials.\n   * Investigate if the same credentials made other unauthorized API calls.\n\n## Changelog\n1 April 2022 - Updated rule and signal message.\n\n[1]: https://docs.aws.amazon.com/detective/latest/APIReference/API_DeleteGraph.html\n\n"
  name               = "[TBOL] AWS Detective Graph deleted"

  options {
    decrease_criticality_based_on_env = "true"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    query           = "source:cloudtrail @eventSource:detective.amazonaws.com @evt.name:DeleteGraph"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_u4f-jje-yse" {
  case {
    condition = "a > 0"
    status    = "high"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an EBS snapshot is made public.\n\n## Strategy\nThis rule lets you monitor these CloudTrail API calls to detect when an EBS snapshot is made public:\n\n* [ModifySnapshotAttribute][1]\n\nThis rule inspects the `@requestParameters.createVolumePermission.add.items.group` array to determine if the string `all` is contained. This is the indicator which means the EBS snapshot is made public.\n\n## Triage and response\n1. Determine if the EBS snapshot should be made public.\n2. Determine which user, `{{@@userIdentity.arn}}`,  in your organization made the EBS snapshot public.\n3. Contact the user to see if they intended to make the EBS snapshot public.\n4. If the user did not make the API call:\n * Rotate the credentials.\n * Investigate if the same credentials made other unauthorized API calls.\n\n[1]: https://awscli.amazonaws.com/v2/documentation/api/latest/reference/ec2/modify-snapshot-attribute.html#examples\n"
  name               = "[TBOL] AWS EBS Snapshot Made Public"

  options {
    decrease_criticality_based_on_env = "true"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    query           = "source:cloudtrail @evt.name:ModifySnapshotAttribute @requestParameters.createVolumePermission.add.items.group:\"all\""
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_ud2-cyr-lzy" {
  case {
    status = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Event Summary\n`@userIdentity.accessKeyId:` `{{@userIdentity.accessKeyId}}` had activity from `{{@impossible_travel.triggering_locations.first_location.city}}, {{@impossible_travel.triggering_locations.first_location.country}}` and `{{@impossible_travel.triggering_locations.second_location.city}}, {{@impossible_travel.triggering_locations.second_location.country}}` which are approximately `{{@impossible_travel.triggering_locations.travel_distance}}km` apart within `{{@impossible_travel.triggering_locations.travel_time_human_readable}}`. This indicates a potential impossible travel.\n\n## Goal\nDetect an Impossible Travel event when a `@userIdentity.type:` `{{@userIdentity.type}}` uses an AWS IAM access key in CloudTrail logs.\n\n## Strategy\nThe Impossible Travel detection type's algorithm compares the GeoIP data of the last log and the current log to determine if the IAM user with `@userIdentity.session_name:` `{{@userIdentity.session_name}}`  traveled more than 500km at over 1,000km/hr and used an AWS IAM access key in CloudTrail logs.\n\n## Triage and response\n1. Determine if the `@userIdentity.accessKeyId:` `{{@userIdentity.accessKeyId}}` for `@userIdentity.session_name:` `{{@userIdentity.session_name}}` should be used from `{{@impossible_travel.triggering_locations.first_location.city}}, {{@impossible_travel.triggering_locations.first_location.country}}` and `{{@impossible_travel.triggering_locations.second_location.city}}, {{@impossible_travel.triggering_locations.second_location.country}}`.\n2. If the IAM user should not be used from `{{@impossible_travel.triggering_locations.first_location.city}}, {{@impossible_travel.triggering_locations.first_location.country}}` and `{{@impossible_travel.triggering_locations.second_location.city}}, {{@impossible_travel.triggering_locations.second_location.country}}`, then consider isolating the account and reset credentials.\n3. Audit any user actions that may have occurred after the illegitimate login."
  name               = "[TBOL] User travel was impossible in AWS CloudTrail IAM log"

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
    query           = "source:cloudtrail @userIdentity.type:IAMUser"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_ufg-0ci-k2w" {
  case {
    condition = "sg_opened_by_automated_service > 0"
    name      = "Event generated by automated service"
    status    = "medium"
  }

  case {
    condition = "sg_mysql_port > 0"
    name      = "MySQL"
    status    = "high"
  }

  case {
    condition = "sg_postgres_port > 0"
    name      = "PostgresSQL"
    status    = "high"
  }

  case {
    condition = "sg_mssql_port > 0"
    name      = "MSSQL"
    status    = "high"
  }

  case {
    condition = "sg_mongodb_port > 0"
    name      = "MongoDB"
    status    = "high"
  }

  case {
    condition = "sg_redis_port > 0"
    name      = "redis"
    status    = "high"
  }

  case {
    condition = "sg_couchdb_http_port > 0"
    name      = "CouchDB HTTP"
    status    = "high"
  }

  case {
    condition = "sg_couchdb_https_port > 0"
    name      = "CouchDB HTTPS"
    status    = "high"
  }

  case {
    condition = "sg_elastic_search_port > 0"
    name      = "Elasticsearch"
    status    = "high"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an AWS security group is opened to the world on a port commonly associated with a database service.\n\n## Strategy\nMonitor CloudTrail and detect when an AWS security group has been created or modified with one of the following API calls:\n* [`AuthorizeSecurityGroupIngress`][1]\n\nThis rule inspects the `@requestParameters.ipPermissions.items.ipRanges.items.cidrIp` or `@requestParameters.cidrIp` array to determine if either of the strings are contained - `0.0.0.0/0` or `::/0` for the following ports:\n* 1433 (MSSQL)\n* 3306 (MySQL)\n* 5432 (PostgresSQL)\n* 5984/6984 (CouchDB)\n* 6379 (Redis)\n* 9200 (Elasticsearch)\n* 27017 (MongoDB)\n\nDatabase ports that are open to the world are a common target for attackers to gain unauthorized access to resources or data.\n\n**Note:** There is a separate rule to detect AWS [Security Group Open to the World][2].\n\n## Triage and response\n1. Determine if `{{@userIdentity.session_name}}` should have made a `{{@evt.name}}` API call.\n2. If the API call was not made by the user:\n  * Rotate the user credentials.\n  * Determine what other API calls were made by the user.\n  * Investigate VPC flow logs and OS system logs to determine if unauthorized access occurred.\n3. If the API call was made legitimately by the user:\n  * Advise the user to modify the IP range to the company private network or bastion host.\n4. Revert security group configuration back to known good state if required:\n  * Use the `aws-cli` command [`revoke-security-group-ingress`][3] or the [AWS console][4] to remove the rule.\n  * Use the `aws-cli` command [`modify-security-group-rules`][5] or [AWS console][6] to modify the existing rule.\n\n[1]: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_AuthorizeSecurityGroupIngress.html\n[2]: https://docs.datadoghq.com/security_platform/default_rules/aws-security-group-open-to-world/\n[3]: https://docs.aws.amazon.com/cli/latest/reference/ec2/revoke-security-group-ingress.html\n[4]: https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#deleting-security-group-rules\n[5]: https://docs.aws.amazon.com/cli/latest/reference/ec2/modify-security-group-rules.html\n[6]: https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#updating-security-group-rules"
  name               = "[TBOL] Potential database port open to the world via AWS security group"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "sg_opened_by_automated_service"
    query           = "source:cloudtrail @eventSource:ec2.amazonaws.com @eventName:AuthorizeSecurityGroupIngress (@requestParameters.ipPermissions.items.ipRanges.items.cidrIp:(\"0.0.0.0/0\" OR \"::/0\") OR @requestParameters.cidrIp:(\"0.0.0.0/0\" OR \"::/0\")) (@requestParameters.fromPort:(3306 OR 5432 OR 1433 OR 27017 OR 6379 OR 5984 OR 6984 OR 9200) OR @requestParameters.ipPermissions.items.fromPort:(3306 OR 5432 OR 1433 OR 27017 OR 6379 OR 5984 OR 6984 OR 9200) OR @requestParameters.toPort:(3306 OR 5432 OR 1433 OR 27017 OR 6379 OR 5984 OR 6984 OR 9200) OR @requestParameters.ipPermissions.items.toPort:(3306 OR 5432 OR 1433 OR 27017 OR 6379 OR 5984 OR 6984 OR 9200)) @http.useragent:cloudformation.amazonaws.com @userIdentity.invokedBy:cloudformation.amazonaws.com"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "sg_mysql_port"
    query           = "source:cloudtrail @eventSource:ec2.amazonaws.com @eventName:AuthorizeSecurityGroupIngress (@requestParameters.ipPermissions.items.ipRanges.items.cidrIp:(\"0.0.0.0/0\" OR \"::/0\") OR @requestParameters.cidrIp:(\"0.0.0.0/0\" OR \"::/0\")) (@requestParameters.fromPort:3306 OR @requestParameters.ipPermissions.items.fromPort:3306 OR @requestParameters.toPort:3306 OR @requestParameters.ipPermissions.items.toPort:3306)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "sg_postgres_port"
    query           = "source:cloudtrail @eventSource:ec2.amazonaws.com @eventName:AuthorizeSecurityGroupIngress (@requestParameters.ipPermissions.items.ipRanges.items.cidrIp:(\"0.0.0.0/0\" OR \"::/0\") OR @requestParameters.cidrIp:(\"0.0.0.0/0\" OR \"::/0\")) (@requestParameters.fromPort:5432 OR @requestParameters.ipPermissions.items.fromPort:5432 OR @requestParameters.toPort:5432 OR @requestParameters.ipPermissions.items.toPort:5432)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "sg_mssql_port"
    query           = "source:cloudtrail @eventSource:ec2.amazonaws.com @eventName:AuthorizeSecurityGroupIngress (@requestParameters.ipPermissions.items.ipRanges.items.cidrIp:(\"0.0.0.0/0\" OR \"::/0\") OR @requestParameters.cidrIp:(\"0.0.0.0/0\" OR \"::/0\")) (@requestParameters.fromPort:1433 OR @requestParameters.ipPermissions.items.fromPort:1433 OR @requestParameters.toPort:1433 OR @requestParameters.ipPermissions.items.toPort:1433)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "sg_mongodb_port"
    query           = "source:cloudtrail @eventSource:ec2.amazonaws.com @eventName:AuthorizeSecurityGroupIngress (@requestParameters.ipPermissions.items.ipRanges.items.cidrIp:(\"0.0.0.0/0\" OR \"::/0\") OR @requestParameters.cidrIp:(\"0.0.0.0/0\" OR \"::/0\")) (@requestParameters.fromPort:27017 OR @requestParameters.ipPermissions.items.fromPort:27017 OR @requestParameters.toPort:27017 OR @requestParameters.ipPermissions.items.toPort:27017)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "sg_redis_port"
    query           = "source:cloudtrail @eventSource:ec2.amazonaws.com @eventName:AuthorizeSecurityGroupIngress (@requestParameters.ipPermissions.items.ipRanges.items.cidrIp:(\"0.0.0.0/0\" OR \"::/0\") OR @requestParameters.cidrIp:(\"0.0.0.0/0\" OR \"::/0\")) (@requestParameters.fromPort:6379 OR @requestParameters.ipPermissions.items.fromPort:6379 OR @requestParameters.toPort:6379 OR @requestParameters.ipPermissions.items.toPort:6379)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "sg_couchdb_http_port"
    query           = "source:cloudtrail @eventSource:ec2.amazonaws.com @eventName:AuthorizeSecurityGroupIngress (@requestParameters.ipPermissions.items.ipRanges.items.cidrIp:(\"0.0.0.0/0\" OR \"::/0\") OR @requestParameters.cidrIp:(\"0.0.0.0/0\" OR \"::/0\")) (@requestParameters.fromPort:5984 OR @requestParameters.ipPermissions.items.fromPort:5984 OR @requestParameters.toPort:5984 OR @requestParameters.ipPermissions.items.toPort:5984)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "sg_couchdb_https_port"
    query           = "source:cloudtrail @eventSource:ec2.amazonaws.com @eventName:AuthorizeSecurityGroupIngress (@requestParameters.ipPermissions.items.ipRanges.items.cidrIp:(\"0.0.0.0/0\" OR \"::/0\") OR @requestParameters.cidrIp:(\"0.0.0.0/0\" OR \"::/0\")) (@requestParameters.fromPort:6984 OR @requestParameters.ipPermissions.items.fromPort:6984 OR @requestParameters.toPort:6984 OR @requestParameters.ipPermissions.items.toPort:6984)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "sg_elastic_search_port"
    query           = "source:cloudtrail @eventSource:ec2.amazonaws.com @eventName:AuthorizeSecurityGroupIngress (@requestParameters.ipPermissions.items.ipRanges.items.cidrIp:(\"0.0.0.0/0\" OR \"::/0\") OR @requestParameters.cidrIp:(\"0.0.0.0/0\" OR \"::/0\")) (@requestParameters.fromPort:9200 OR @requestParameters.ipPermissions.items.fromPort:9200 OR @requestParameters.toPort:9200 OR @requestParameters.ipPermissions.items.toPort:9200)"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_hvc-dgx-6pz" {
  case {
    condition = "sg_open_to_world > 0"
    name      = "SG open to world"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an AWS security group is opened to the world.\n\n## Strategy\nMonitor CloudTrail and detect when an AWS security group has been created or modified with one of the following API calls:\n* [AuthorizeSecurityGroupIngress][1]\n\nThis rule inspects the `@requestParameters.ipPermissions.items.ipRanges.items.cidrIp` array to determine if either of the strings are contained:\n* `0.0.0.0/0`\n* `::/0`\n\n## Triage and response\n1. Determine who the user was who made this API call.\n2. Contact the user and see if this was an API call which was made by the user.\n3. If the API call was not made by the user:\n  * Rotate the user credentials and investigate what other API calls.\n  * Determine what other API calls the user made which were not made by the user.\n\n[1]: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_AuthorizeSecurityGroupIngress.html\n\n## Changelog\n18 March 2022 - Updated rule query.\n"
  name               = "[TBOL] Security group open to the world"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@usr.account_id"]
    name            = "sg_open_to_world"
    query           = "source:cloudtrail @evt.name:AuthorizeSecurityGroupIngress @requestParameters.ipPermissions.items.ipRanges.items.cidrIp:(\"0.0.0.0/0\" OR \"::/0\")"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_vrh-ml0-134" {
  case {
    condition = "stop_instance > 0 \u0026\u0026 modify_instance_attribute > 0 \u0026\u0026 start_instance > 0"
    status    = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect a user attempting to modify a [user data script][1] on an EC2 instance.\n\n## Strategy\nThis rule allows you to monitor CloudTrail and detect if an attacker has attempted to modify the user data script on an EC2 instance using the following API calls:\n\n* [`StopInstances`][2]\n* [`ModifyInstanceAttribute`][3]\n* [`StartInstances`][4]\n\n## Triage and response\n1. Determine if `{{@userIdentity.session_name}}` should have modified the user data script associated with `{{host}}`.\n2. If the API calls were not made by the user:\n  * Rotate user credentials.\n  * Determine what other API calls were made by the user.\n  * Follow your company's incident response process to determine the impact to `{{host}}`.\n  * Revert the user data script to the last known good state with the `aws-cli` command [modify-instance-attribute][5] or use the [AWS Console][6].\n3. If the API calls were made by the user:\n  * Determine if the user should be modifying this user data script.\n  * If No, see if other API calls were made by the user and determine if they warrant further investigation.\n\n[1]: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/user-data.html\n[2]: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_StopInstances.html\n[3]: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ModifyInstanceAttribute.html\n[4]: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_StartInstances.html\n[5]: https://docs.aws.amazon.com/cli/latest/reference/ec2/modify-instance-attribute.html\n[6]: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/user-data.html#user-data-view-change"
  name               = "[TBOL] Possible AWS EC2 privilege escalation via the modification of user data"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "900"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "stop_instance"
    query           = "source:cloudtrail @eventSource:ec2.amazonaws.com @evt.name:StopInstances ((-@http.useragent:opsworks.amazonaws.com -@userIdentity.invokedBy:opsworks.amazonaws.com) (-@http.useragent:cloudformation.amazonaws.com -@userIdentity.invokedBy:cloudformation.amazonaws.com))"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "modify_instance_attribute"
    query           = "source:cloudtrail @eventSource:ec2.amazonaws.com @evt.name:ModifyInstanceAttribute @requestParameters.userData:* ((-@http.useragent:opsworks.amazonaws.com -@userIdentity.invokedBy:opsworks.amazonaws.com) (-@http.useragent:cloudformation.amazonaws.com -@userIdentity.invokedBy:cloudformation.amazonaws.com))"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "start_instance"
    query           = "source:cloudtrail @eventSource:ec2.amazonaws.com @evt.name:StartInstances ((-@http.useragent:opsworks.amazonaws.com -@userIdentity.invokedBy:opsworks.amazonaws.com) (-@http.useragent:cloudformation.amazonaws.com -@userIdentity.invokedBy:cloudformation.amazonaws.com))"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_wiy-wzh-ndf" {
  case {
    condition = "a > 0"
    status    = "high"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a user disassociates a VPC from the query logging configuration.\n\n## Strategy\nThis rule lets you monitor this CloudTrail API call to detect if a user has disassociated.\n\n* [DisassociateResolverQueryLogConfig][1]\n\n## Triage and response\n1. Determine if {{@userIdentity.arn}} is expected to perform the {{@evt.name}} API call.\n2. Contact the principal owner and see if this was an API call that was made by the user.\n3. If the API call was not made by the user, rotate the user credentials and investigate what other APIs were successfully accessed.\n   * Rotate the credentials.\n   * Investigate if the same credentials made other unauthorized API calls.\n\n## Changelog\n7 April 2022 - Update rule and signal message.\n\n[1]: https://docs.aws.amazon.com/Route53/latest/APIReference/API_route53resolver_DisassociateResolverQueryLogConfig.html"
  name               = "[TBOL] AWS Route 53 VPC disassociated from query logging configuration"

  options {
    decrease_criticality_based_on_env = "true"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    query           = "source:cloudtrail -@level:Error @evt.name:DisassociateResolverQueryLogConfig"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_wqw-oju-hiy" {
  case {
    condition = "security_group_created > 0"
    name      = "security group created"
    status    = "info"
  }

  case {
    condition = "security_group_modified > 0"
    name      = "security group modified"
    status    = "info"
  }

  case {
    condition = "security_group_deleted > 0"
    name      = "security group deleted"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an AWS security group has been modified.\n\n## Strategy\nMonitor CloudTrail and detect when an AWS security group has been created or modified with one of the following API calls:\n* [AuthorizeSecurityGroupIngress][1] \n* [AuthorizeSecurityGroupEgress][2] \n* [RevokeSecurityGroupIngress][3] \n* [RevokeSecurityGroupEgress][4] \n* [CreateSecurityGroup][5] \n* [DeleteSecurityGroup][6]\n\n\n**Note:**  There is a separate rule to detect AWS Security Group Open to the World.\n\n## Triage and response\n1. Determine who the user was who made this API call.\n2. Contact the user and see if this was an API call which was made by the user.\n3. If the API call was not made by the user:\n   * Rotate the user credentials and investigate what other API calls.\n   * Determine what other API calls the user made which were not made by the user.\n\n[1]: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_AuthorizeSecurityGroupIngress.html \n [2]: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_AuthorizeSecurityGroupEgress.html \n [3]: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_RevokeSecurityGroupIngress.html \n [4]: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_RevokeSecurityGroupEgress.html \n [5]: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateSecurityGroup.html \n [6]: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DeleteSecurityGroup.html\n\n## Changelog\n18 March 2022 - Updated severity, split query into multiple queries, and split the single case into multiple cases."
  name               = "[TBOL] AWS security group created, modified or deleted"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "security_group_created"
    query           = "source:cloudtrail @evt.name:CreateSecurityGroup -@requestParameters.ipPermissions.items.ipRanges.items.cidrIp:(\"0.0.0.0/0\" OR \"::/0\")"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "security_group_modified"
    query           = "source:cloudtrail @evt.name:(AuthorizeSecurityGroupIngress OR AuthorizeSecurityGroupEgress OR RevokeSecurityGroupIngress OR RevokeSecurityGroupEgress) -@requestParameters.ipPermissions.items.ipRanges.items.cidrIp:(\"0.0.0.0/0\" OR \"::/0\")"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "security_group_deleted"
    query           = "source:cloudtrail @evt.name:DeleteSecurityGroup -@requestParameters.ipPermissions.items.ipRanges.items.cidrIp:(\"0.0.0.0/0\" OR \"::/0\")"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_x2y-rqy-pbh" {
  case {
    condition = "a > 0"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect potential persistence mechanisms being deployed in the AWS Elastic Container Registry (ECR).\n\nNOTE: Amazon ECR requires that users have permission to make calls to the `ecr:GetAuthorizationToken` API through an IAM policy before they can authenticate to a registry and push or pull any images from any Amazon ECR repository.\n\n## Strategy\nDetect when `@evt.name:PutImage` is used against the `ecr.amazonaws.com` API. \n\n## Triage \u0026 Response\n1. Check that `{{@responseElements.image.imageId.imageDigest}}` is a valid sha256 hash for the container image with a tag of `{{@responseElements.image.imageId.imageTag}}` in the `{{@responseElements.image.repositoryName}}` repository on AWS Account `{{@usr.account_id}}`.\n2. If the hash is not valid for that container image, determine if the container image was placed there for a malicious purpose."
  name               = "[TBOL] New Private Repository Container Image detected in AWS ECR"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@requestParameters.repositoryName"]
    name            = "a"
    query           = "source:cloudtrail @eventSource:ecr.amazonaws.com @evt.name:PutImage -@error.kind:ImageAlreadyExistsException @threat_intel.indicators_matched:*"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_x6j-t82-syz" {
  case {
    status = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when the `AdministratorAccess` policy is attached to an AWS IAM group.\n\n## Strategy\nThis rule allows you to monitor CloudTrail and detect if an attacker has attached the AWS managed policy [`AdministratorAccess`][1] to a new AWS IAM group using the [`AttachGroupPolicy`][2] API call.\n\n## Triage and response\n1. Determine if `{{@userIdentity.session_name}}` should have made a `{{@evt.name}}` API call.\n2. If the API call was not made by the user:\n  * Rotate user credentials.\n  * Determine what other API calls were made by the user.\n  * Remove the `AdministratorAccess` policy from the `{{@requestParameters.groupName}}` group using the `aws-cli` command [detach-group-policy][3].\n3. If the API call was made legitimately by the user:\n  * Determine if the group `{{@requestParameters.groupName}}` requires the `AdministratorAccess` policy to perform the intended function.\n  * Advise the user to find the [least privileged][4] policy that allows the group to operate as intended.\n\n[1]: https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_job-functions.html#jf_administrator\n[2]: https://docs.aws.amazon.com/IAM/latest/APIReference/API_AttachGroupPolicy.html\n[3]: https://docs.aws.amazon.com/cli/latest/reference/iam/detach-group-policy.html\n[4]: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privilege"
  name               = "[TBOL] AWS IAM privileged policy was applied to a group"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "new_value"
    evaluation_window                 = "0"
    keep_alive                        = "1800"
    max_signal_duration               = "1800"

    new_value_options {
      forget_after       = "7"
      learning_duration  = "1"
      learning_method    = "duration"
      learning_threshold = "0"
    }
  }

  query {
    aggregation     = "new_value"
    group_by_fields = ["@userIdentity.arn"]
    metric          = "@requestParameters.groupName"
    metrics         = ["@requestParameters.groupName"]
    query           = "source:cloudtrail @eventSource:iam.amazonaws.com @evt.name:AttachGroupPolicy @requestParameters.policyArn:\"arn:aws:iam::aws:policy/AdministratorAccess\""
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_xis-umn-x8r" {
  case {
    condition = "a > 0"
    status    = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a KMS (Key Management Service) key is deleted or scheduled for deletion.\n\n## Strategy\nThis rule lets you monitor these CloudTrail API calls to detect if an attacker is deleting KMS keys:\n* [DisableKey][1]\n* [ScheduleKeyDeletion][2]\n\n## Triage and response\n1. Determine if `user ARN:` {{@userIdentity.arn}} in your organization should be making this call.\n2. If the user did not make the API call:\n * Rotate the credentials.\n * Use the `Cloud SIEM - User Investigation` OOTB dashboard to investigate other potential unauthorized API calls from this user.\n\n[1]: https://docs.aws.amazon.com/kms/latest/APIReference/API_DisableKey.html\n[2]: https://docs.aws.amazon.com/kms/latest/APIReference/API_ScheduleKeyDeletion.html \n\n## Changelog\n16 March 2022 - Rule severity and markdown updated."
  name               = "[TBOL] AWS KMS key deleted or scheduled for deletion"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    query           = "source:cloudtrail @evt.name:(DisableKey OR ScheduleKeyDeletion)"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_xkg-tna-cey" {
  case {
    condition = "a > 0"
    status    = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an attacker is removing a FlowLogs collector.\n\n## Strategy\nThis rule lets you monitor this EC2 API call:\n\n* [DeleteFlowLogs][1]\n\n## Triage and response\n1. Determine if arn: {{@userIdentity.arn}} should make this API call.\n2. Contact the user to see if they intended to make this API call.\n3. If the user did not make the API call:\n * Rotate the credentials.\n * Investigate if the same credentials made other unauthorized API calls.\n\n## Changelog\n4 April 2022 - Rule query and signal message updated.\n\n[1]: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DeleteFlowLogs.html\n"
  name               = "[TBOL] AWS FlowLogs removed"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    query           = "source:cloudtrail @evt.name:DeleteFlowLogs -@responseElements.DeleteFlowLogsResponse.unsuccessful:\"\""
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_hr3-ijn-4qm" {
  case {
    condition = "a > 0"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an attacker is trying to evade defenses by deleting or disabling EventBridge rules.\n\n## Strategy\nThis rule lets you monitor these CloudTrail API calls to detect if an attacker is modifying or disabling EventBridge rules:\n\n* [DeleteRule][1]\n* [DisableRule][2]\n\n## Triage and response\n1. Determine if the arn: {{@userIdentity.arn}} should have made the {{@evt.name}} API call.\n2. Contact the user to see if they intended to make this API call.\n3. If the user did not make the API call:\n * Rotate the credentials.\n * Investigate if the same credentials made other unauthorized API calls.\n\n**NOTE:** Your organization should tune out user agents that are valid and triggering this signal. To do this, see our [Fine-tune security signals to reduce noise][3] blog.\n\n## Changelog\n4 April 2022 - Rule query, options and signal markdown updated.\n\n[1]: https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_DeleteRule.html\n[2]: https://docs.aws.amazon.com/eventbridge/latest/APIReference/API_DisableRule.html\n[3]: https://www.datadoghq.com/blog/writing-datadog-security-detection-rules/#fine-tune-security-signals-to-reduce-noise\n"
  name               = "[TBOL] AWS EventBridge rule disabled or deleted"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "86400"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn", "@requestParameters.name"]
    query           = "source:cloudtrail @eventSource:events.amazonaws.com @evt.name:(DeleteRule OR DisableRule)"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_hdg-gt0-kth" {
  case {
    status = "high"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetects when an application on a host has a new, unrecognized API call.\n\n## Strategy\nUsing the `New Value` detection method, find when an `application` has a new `@evt.name` on a `host`.\n\n## Triage and response\n1. Determine if the `host: {{host}}` running the `application: {{application}}` should have done the following event(s)`{{@evt.name}}`:\n   * If yes, you can `Archive` the signal.\n   * If no, investigate further by clicking on the **Suggested Actions** tab for the signal\n2. If necessary, initiate your company's incident response process.\n\n"
  name               = "[TBOL] AWS EC2 new event for application"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "new_value"
    evaluation_window                 = "0"
    keep_alive                        = "3600"
    max_signal_duration               = "86400"

    new_value_options {
      forget_after       = "7"
      learning_duration  = "7"
      learning_method    = "duration"
      learning_threshold = "0"
    }
  }

  query {
    aggregation     = "new_value"
    group_by_fields = ["application"]
    metric          = "@evt.name"
    metrics         = ["@evt.name"]
    query           = "source:cloudtrail host:i-*"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_y5x-cxm-m77" {
  case {
    condition = "aws_guardduty_threatintel_set_deleted > 0"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an attacker is trying to evade defenses by deleting a GuardDuty ThreatIntelSet.\n\n## Strategy\nThis rule lets you monitor this CloudTrail API call to detect if an attacker is deleting a GuardDuty ThreatIntelSet:\n\n* [DeleteThreatIntelSet][1]\n\n## Triage and response\n1. Determine if user: `{{@userIdentity.arn}}` should have made a `{{@evt.name}}` API call.\n2. If the API call was not made by the user:\n  * Rotate user credentials.\n  * Determine what other API calls were made by the user.\n  * Replace ThreatIntelSets deleted by the user with the `aws-cli` command [create-threat-intel-set][2] or use the [AWS Console][3].\n3. If the API call was made by the user:\n  * Determine if the user should be performing this API call and if it was an authorized change.\n  * If No, see if other API calls were made by the user and determine if they warrant further investigation.\n\n[1]: https://docs.aws.amazon.com/guardduty/latest/APIReference/API_DeleteThreatIntelSet.html\n[2]: https://docs.aws.amazon.com/cli/latest/reference/guardduty/create-threat-intel-set.html\n[3]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_upload-lists.html"
  name               = "[TBOL] AWS GuardDuty threat intel set deleted"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "aws_guardduty_threatintel_set_deleted"
    query           = "source:cloudtrail @evt.name:DeleteThreatIntelSet"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_y7t-ksu-ivr" {
  case {
    status = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an attacker accesses your AWS account from their AWS Account.\n\n## Strategy\nThis rule lets you monitor AssumeRole (`@evt.name:AssumeRole`) CloudTrail API calls to detect when an external AWS account (`@usr.account_id`) assumes a role into your AWS account (`account`). It does this by learning all AWS accounts from which the AssumeRole call occurs within a 7-day window. Newly detected accounts after this 7-day window will generate security signals.\n\n## Triage and response\n1. Determine if the `@usr.account_id` is an AWS account is managed by your company.\n2. If not, try to determine who is the owner of the AWS account.\n3. Inspect the role the account is assuming. Determine who created this role and who allowed this AWS account to assume this role.\n\n## Changelog\n7 April 2022 - Update rule query and signal message.\n"
  name               = "[TBOL] New AWS Account Seen Assuming a Role into AWS Account"

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
    group_by_fields = ["account"]
    metric          = "@usr.account_id"
    metrics         = ["@usr.account_id"]
    query           = "source:cloudtrail -@level:Error @evt.name:AssumeRole"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_yqa-k79-hg1" {
  case {
    condition = "a > 0"
    status    = "high"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a CloudWatch Log Group is deleted. \n\n## Strategy\nDetect when a `@evt.name:DeleteLogGroup` event occurs successfully.\n\n## Triage and response\n1. Ensure that the `{{@requestParameters.logGroupName}}` log group is not used for auditing or security purposes.\n2. If it is then:\n    * Ensure that the user: `{{@userIdentity.session_name}}` should be making this type of API call to your `{{env}}` environment.\n    * Consider whitelisting the log group name: `{{@requestParameters.logGroupName}}` via a [suppression list][1]\n3. If not, begin your company's IR process and investigate.\n\n[1] https://www.datadoghq.com/blog/writing-datadog-security-detection-rules/#customize-security-signal-messages-to-fit-your-environment"
  name               = "[TBOL] AWS CloudWatch log group deleted"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    query           = "source:cloudtrail @evt.name:DeleteLogGroup -@level:Error -@http.useragent:(cloudformation.amazonaws.com OR *www.terraform.io*) -@userIdentity.invokedBy:cloudformation.amazonaws.com"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_yqg-ihl-vaj" {
  case {
    condition = "list_buckets_access_denied > 0"
    name      = "Access denied for ListBuckets"
    status    = "low"
  }

  case {
    condition = "list_buckets_success > 0"
    name      = "Successful ListBuckets"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an EC2 instance makes an API call to AWS to list all of the S3 Buckets.\n\n## Strategy\nThis rule lets you monitor CloudTrail to detect a [ListBuckets][1] API call with the session name prefixed with `i-`. A session name prefixed with `i-` typically indicates that it is an EC2 instance using an [Instance Profile][2] to communicate with other AWS services, which is a common attacker technique to see the full list of S3 buckets in your AWS account.\n\n## Triage and response\n1. Determine if the EC2 instance should be making this API call.\n* If **not a legitimate** user/application, rotate the credentials, verify what else may have been accessed and open an investigation into how this instance was compromised.\n* If a **legitimate** user/application on the EC2 instance is making the `ListBuckets` API call, consider whether this API call is really needed.  \n\n[1]: https://docs.aws.amazon.com/AmazonS3/latest/API/API_ListBuckets.html\n[2]: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html#ec2-instance-profile\n\n## Changelog\n18 March 2022 - Updated rule severity and rule name."
  name               = "[TBOL] An EC2 instance attempted to enumerate S3 bucket"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "list_buckets_access_denied"
    query           = "source:cloudtrail @userIdentity.session_name:i-* @evt.name:ListBuckets @error.kind:AccessDenied"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "list_buckets_success"
    query           = "source:cloudtrail @userIdentity.session_name:i-* @evt.name:ListBuckets -@error.kind:*"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_ysw-kuy-swb" {
  case {
    condition = "a > 0"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a new image is uploaded to the public ECR. This could be a potential exfil route of data from the cloud. Could be a supply chain effect as well if a company hosts their containers here for consumers.\n\nNOTE: Amazon ECR requires that users have permission to make calls to the `ecr-public:GetAuthorizationToken` and `sts:GetServiceBearerToken` API through an IAM policy before they can authenticate to a registry and push any images to an Amazon ECR repository.\n\n## Strategy\nDetect when `@evt.name:PutImage` is used against the `ecr-public.amazonaws.com` API. \n\n## Triage \u0026 Response\n1. Check that `{{@responseElements.image.imageId.imageDigest}}` is a valid sha256 hash for the container image with a tag of `{{@responseElements.image.imageId.imageTag}}` in the `{{@responseElements.image.repositoryName}}` repository on AWS Account `{{@usr.account_id}}`.\n2. If the hash is not valid for that container image, determine if the container image was placed there for a malicious purpose.\n"
  name               = "[TBOL] New Public Repository Container Image detected in AWS ECR"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@requestParameters.repositoryName"]
    name            = "a"
    query           = "source:cloudtrail @eventSource:ecr-public.amazonaws.com @evt.name:PutImage -@error.kind:ImageAlreadyExistsException"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_yys-ufd-ifa" {
  case {
    status = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an attacker spawns an instance for malicious purposes. \n\n## Strategy\nThis rule lets you monitor this CloudTrail API call to detect when a new instance type (`@responseElements.instancesSet.items.instanceType`) is spawned:\n\n* [RunInstances][1]\n\nIt does this by inspecting the AWS Instance types each AWS account are seen over a 7-day window. Newly detected instance types after this 7-day window till generate security signals.\n\n## Triage and response\n1. Determine whether the instance type `{{@responseElements.instancesSet.items.instanceType}}` is expected to be used in your AWS account by checking the [Datadog Infrastructure List][2].\n2. If not, determine who spawned this instance and ask the user whether their activity was legitimate or whether their credentials were compromised and this instance is being used by an attacker.\n\n## Changelog\n7 April 2022 - Updated rule query.\n\n[1]: https://docs.aws.amazon.com/cli/latest/reference/ec2/run-instances.html\n[2]: https://app.datadoghq.com/infrastructure?tab=details\u0026tags=instance-type%3A{{@responseElements.instancesSet.items.instanceType}}"
  name               = "[TBOL] New EC2 Instance Type"

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
    group_by_fields = ["account"]
    metric          = "@responseElements.instancesSet.items.instanceType"
    metrics         = ["@responseElements.instancesSet.items.instanceType"]
    query           = "source:cloudtrail -@level:Error @eventSource:ec2.amazonaws.com @evt.name:RunInstances"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_zey-uwy-0yq" {
  case {
    status = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect an Impossible Travel event when a `@userIdentity.type:` `{{@userIdentity.type}}` uses an AWS IAM access key and filter out VPNs and AWS Internal IPs.\n\n## Strategy\nThe Impossible Travel detection type's algorithm compares the GeoIP data of the last log and the current log to determine if the IAM user with `@userIdentity.session_name:` `{{@userIdentity.session_name}}`  traveled more than 500km at over 1,000km/hr and used an AWS IAM access key.\n\n## Triage and response\n1. Determine if the `@userIdentity.accessKeyId:` `{{@userIdentity.accessKeyId}}` for `@userIdentity.session_name:` `{{@userIdentity.session_name}}` should be used from `{{@impossible_travel.triggering_locations.first_location.city}}, {{@impossible_travel.triggering_locations.first_location.country}}` and `{{@impossible_travel.triggering_locations.second_location.city}}, {{@impossible_travel.triggering_locations.second_location.country}}`.\n2. If the IAM user should not be used from `{{@impossible_travel.triggering_locations.first_location.city}}, {{@impossible_travel.triggering_locations.first_location.country}}` and `{{@impossible_travel.triggering_locations.second_location.city}}, {{@impossible_travel.triggering_locations.second_location.country}}`, then consider isolating the account and reset credentials.\n3. Audit any user actions that may have occurred after the illegitimate login.\n\n## Changelog\n- 7 April 2022 - Updated signal message.\n- 3 August 2022 - Fixed null groupby field in query."
  name               = "[TBOL] Compromised AWS IAM User Access Key"

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
    group_by_fields = ["@userIdentity.accessKeyId", "@usr.name"]
    metric          = "@network.client.geoip"
    metrics         = ["@network.client.geoip"]
    query           = "source:cloudtrail -@level:Error @userIdentity.type:IAMUser -@network.client.geoip.invalidAddress:\"AWS Internal\" -@threat_intel.results.category:anonymizer"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_zfj-5xx-32x" {
  case {
    condition = "create_gateway > 0"
    name      = "create gateway"
    status    = "info"
  }

  case {
    condition = "delete_gateway > 0"
    name      = "delete gateway"
    status    = "info"
  }

  case {
    condition = "modify_gateway > 0"
    name      = "modify gateway"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an AWS Network Gateway has been created or modified.\n\n## Strategy\nMonitor CloudTrail and detect when an AWS Network Gateway has been created or modified with one of the following API calls:\n* [CreateCustomerGateway][1] \n* [DeleteCustomerGateway][2] \n* [AttachInternetGateway][3] \n* [CreateInternetGateway][4]\n* [DeleteInternetGateway][5] \n* [DetachInternetGateway][6]\n\n## Triage and response\n1. Determine if the API call: {{@evt.name}} should have occurred.\n2. If it shouldn't have been made:\n   * Contact the user: {{@userIdentity.arn}} and see if they made the API call.\n3. If the API call was not made by the user:\n   * Rotate the user credentials.\n   * Determine what other API calls were made with the old credentials that were not made by the user.\n\n## Changelog\n6 April 2022 - Updated rule cases and signal message.\n\n[1]: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateCustomerGateway \n[2]: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DeleteCustomerGateway \n[3]: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_AttachInternetGateway \n[4]: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateInternetGateway \n[5]: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DeleteInternetGateway \n[6]: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DetachInternetGateway.html\n"
  name               = "[TBOL] AWS Network Gateway created or modified"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "43200"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "create_gateway"
    query           = "source:cloudtrail -@level:Error @evt.name:(CreateCustomerGateway OR CreateInternetGateway)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "delete_gateway"
    query           = "source:cloudtrail -@level:Error @evt.name:(DeleteCustomerGateway OR DeleteInternetGateway)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "modify_gateway"
    query           = "source:cloudtrail @evt.name:(AttachInternetGateway OR DetachInternetGateway)"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_4zw-tqi-dob" {
  case {
    condition = "vpc_deleted > 0"
    name      = "vpc deleted"
    status    = "info"
  }

  case {
    condition = "vpc_created > 0"
    name      = "vpc created"
    status    = "info"
  }

  case {
    condition = "vpc_modified > 0"
    name      = "vpc modified"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an attacker is destroying a VPC.\n\n## Strategy\nThis rule lets you monitor this CloudTrail API call to detect if an attacker is deleting a VPC:\n\n* [DeleteVpc][1]\n\n## Triage and response\n1. Determine if {{@userIdentity.arn}} is expected to perform the {{@evt.name}} API call on the account: {{@usr.account_id}}.\n2. Contact the principal owner and see if this was an API call that was made by the user.\n3. If the API call was not made by the user, rotate the user credentials and investigate what other APIs were successfully accessed.\n   * Rotate the credentials.\n   * Investigate if the same credentials made other unauthorized API calls.\n\n## Changelog\n7 April 2022 - Updated rule query, cases and signal message.\n\n[1]: https://docs.aws.amazon.com/cli/latest/reference/ec2/delete-vpc.html\n"
  name               = "[TBOL] AWS VPC created or modified"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "86400"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "vpc_deleted"
    query           = "source:cloudtrail -@level:Error @evt.name:(DeleteVpc OR DeleteVpcPeeringConnection)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "vpc_created"
    query           = "source:cloudtrail -@level:Error @evt.name:(CreateVpc OR CreateVpcPeeringConnection)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "vpc_modified"
    query           = "source:cloudtrail -@level:Error @evt.name:(ModifyVpcAttribute OR AcceptVpcPeeringConnection OR RejectVpcPeeringConnection OR AttachClassicLinkVpc OR DetachClassicLinkVpc OR DisableVpcClassicLink OR EnableVpcClassicLink)"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_5yc-yjg-nfq" {
  case {
    status = "high"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an AWS assumed role accesses S3 buckets that they do not usually access. \n\n## Strategy\nMonitor cloudtrail logs to identify when a `@userIdentity.assumed_role` makes an anomalous amount of `GetObject` calls to a unique number of S3 buckets (`@requestParameters.bucketName`).\n\n## Triage and response\n1. Determine if the user using the assumed role: {{@userIdentity.assumed_role}} should be accessing a bunch of random buckets.\n   * Here is a list of buckets that were accessed (up to 10): {{@requestParameters.bucketName}}\n\n## Changelog\n30 Mar 2022 - Updated query and signal message."
  name               = "[TBOL] Anomalous number of S3 buckets accessed"

  options {
    decrease_criticality_based_on_env = "true"
    detection_method                  = "anomaly_detection"
    evaluation_window                 = "1800"
    keep_alive                        = "7200"
    max_signal_duration               = "86400"
  }

  query {
    aggregation     = "cardinality"
    distinct_fields = ["@requestParameters.bucketName"]
    group_by_fields = ["@userIdentity.assumed_role"]
    query           = "source:cloudtrail @evt.name:GetObject -status:error"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_7zo-caj-po5" {
  case {
    condition = "get_passwordata > 0"
    name      = "Error"
    status    = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect a user attempting to retrieve the encrypted Administrator password for a Windows EC2 instance.\n\n## Strategy\nThis rule allows you to monitor CloudTrail and detect if an attacker has attempted to retrieve the encrypted Administrator password for a Windows EC2 instance using the [`GetPasswordData`][1] API call.\n\n## Triage and response\n1. Determine if `{{@userIdentity.session_name}}` should have made a `{{@evt.name}}` API call.\n2. If the API call was not made by the user:\n  * Rotate user credentials.\n  * Determine what other API calls were made by the user.\n3. If the API call was made by the user:\n  * Determine if this user should be accessing this EC2 instance.\n  * If Yes, advise the user to speak with the instance owner to resolve the error.\n  * If No, see if other API calls were made by the user and determine if they warrant further investigation.\n\n[1]: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_GetPasswordData.html"
  name               = "[TBOL] Encrypted administrator password retrieved for Windows EC2 instance"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "get_passwordata"
    query           = "source:cloudtrail @evt.name:GetPasswordData @eventSource:ec2.amazonaws.com status:error"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_8tc-mdt-yq0" {
  case {
    condition = "public_access_block_removed > 0"
    name      = "User removed public access block"
    status    = "critical"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when the S3 Public Access Block configuration has been removed \n\n## Strategy\nThis rule lets you monitor this CloudTrail API call to detect if an attacker is deleting the S3 Public Access Block configuration:\n\n* [DeleteAccountPublicAccessBlock][1]\n\n## Triage and response\n1. Determine who the user was who made this API call.\n2. Contact the user and inform them of best practices of enabling Public Access Block on S3 buckets.\n3. Re-enable Public Access Block on the S3 bucket.\n\nMore details on S3 Public Block Public Access can be found [here][2].\n\n[1]: https://docs.aws.amazon.com/cli/latest/reference/s3api/delete-public-access-block.html\n[2]: https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html\n\n## Changelog\n18 March 2022 - updated severity and query."
  name               = "[TBOL] AWS S3 Public Access Block removed"

  options {
    decrease_criticality_based_on_env = "true"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "public_access_block_removed"
    query           = "source:cloudtrail -@level:error @evt.name:DeleteAccountPublicAccessBlock"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_9iu-e4w-9tu" {
  case {
    condition = "not_cloudformation_action > 0"
    name      = "not a cloudformation action"
    status    = "critical"
  }

  case {
    condition = "cloudformation_action > 0"
    name      = "cloudformation action"
    status    = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a user disables AWS Security Hub.\n\n## Strategy\nThis rule lets you monitor this CloudTrail API call to detect if a user has disabled AWS Security Hub:\n\n* [DisableSecurityHub][1]\n\n## Triage and response\n1. Determine if {{@userIdentity.arn}} is expected to perform the {{@evt.name}} API call on the account: {{@usr.account_id}}.\n2. Contact the principal owner and see if this was an API call that was made by the user.\n3. If the API call was not made by the user, rotate the user credentials and investigate what other APIs were successfully accessed.\n   * Rotate the credentials.\n   * Investigate if the same credentials made other unauthorized API calls.\n\n## Changelog\n7 April 2022 - Updated rule query and signal message.\n\n[1]: https://docs.aws.amazon.com/securityhub/1.0/APIReference/API_DisableSecurityHub.html"
  name               = "[TBOL] AWS Security Hub disabled"

  options {
    decrease_criticality_based_on_env = "true"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "not_cloudformation_action"
    query           = "source:cloudtrail -@network.client.ip:cloudformation.amazonaws.com -@level:Error @evt.name:DisableSecurityHub"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "cloudformation_action"
    query           = "source:cloudtrail @network.client.ip:cloudformation.amazonaws.com -@level:Error @evt.name:DisableSecurityHub"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_9nh-no7-ktx" {
  case {
    condition = "loginprofile > 0"
    status    = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect a user attempting to create a password for a specified IAM user.\n\n## Strategy\nThis rule allows you to monitor CloudTrail and detect if an attacker has attempted to create a password for an IAM user using the [`CreateLoginProfile`][1] API call.\n\n## Triage and response\n1. Determine if `{{@userIdentity.session_name}}` should have made a `{{@evt.name}}` API call.\n2. If the API call was not made by the user:\n  * Rotate user credentials.\n  * Determine what other API calls were made by the user.\n  * Remove any passwords generated by the user with the `aws-cli` command [delete-login-profile][2] or use the [AWS Console][3].\n3. If the API call was made by the user:\n  * Determine if the user should be performing this API call.\n  * If No, see if other API calls were made by the user and determine if they warrant further investigation.\n\n[1]: https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreateLoginProfile.html\n[2]: https://docs.aws.amazon.com/cli/latest/reference/iam/delete-login-profile.html\n[3]: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_admin-change-user.html#id_credentials_passwords_admin-change-user_console"
  name               = "[TBOL] Possible Privilege Escalation via AWS IAM CreateLoginProfile"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "loginprofile"
    query           = "source:cloudtrail @eventSource:iam.amazonaws.com @eventName:CreateLoginProfile status:error"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_ack-3qo-whs" {
  case {
    condition = "leave_organization > 0"
    status    = "high"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect an AWS account attempting to leave an AWS organization.\n\n## Strategy\nThis rule allows you to monitor CloudTrail and detect if an attacker has attempted to have an AWS account leave an AWS organization using the [LeaveOrganization][1] API call.\n\nAn attacker may attempt this API call for several reasons, such as:\n\n* Target security configurations that are often defined at the organization level. Leaving an organization can disrupt or disable these controls.\n* Perform a denial of service (DoS) attack on the victim's account that prevents the victim's organization to access it.\n\n## Triage and response\n1. Determine if `{{@userIdentity.arn}}` should have made the `{{@evt.name}}` API call.\n2. If the API call was not made by the user:\n  * Rotate user credentials.\n  * Determine what other API calls were made by the user.\n  * Initiate your company's incident response (IR) process.\n3. If the API call was made legitimately by the user:\n  * Communicate with the user to understand if this was a planned action.\n  * If No, see if other API calls were made by the user and determine if they warrant further investigation.\n  * Initiate your company's incident response (IR) process.\n\n[1]: https://docs.aws.amazon.com/organizations/latest/APIReference/API_LeaveOrganization.html\n[2]: https://docs.aws.amazon.com/IAM/latest/APIReference/API_AttachGroupPolicy.html\n[3]: https://docs.aws.amazon.com/cli/latest/reference/iam/detach-group-policy.html\n[4]: https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#grant-least-privileg"
  name               = "[TBOL] An AWS account attempted to leave the AWS Organization"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "7200"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "leave_organization"
    query           = "source:cloudtrail @evt.name:LeaveOrganization @eventSource:organizations.amazonaws.com"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_aof-qd6-yi9" {
  case {
    condition = "a > 0"
    status    = "high"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a user deletes a Route 53 query logging configuration.\n\n## Strategy\nMonitor cloudtrail logs where `@evt.name` is `DeleteResolverQueryLogConfig` which would stop Route53 Query logging for all of the Amazon VPCs that are associated with the configuration.\n\n## Triage and response\n1. Determine if {{@userIdentity.arn}} is expected to perform the {{@evt.name}} API call.\n2. Contact the principal owner and see if this was an API call that was made by the user.\n3. If the API call was not made by the user, rotate the user credentials and investigate what other APIs were successfully accessed.\n\n## Changelog\n7 April 2022 - Updated rule query and signal message."
  name               = "[TBOL] AWS Route 53 DNS query logging disabled"

  options {
    decrease_criticality_based_on_env = "true"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    query           = "source:cloudtrail -@level:Error @evt.name:DeleteResolverQueryLogConfig"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_axo-tak-c4w" {
  case {
    condition = "waf_webacl_update > 0"
    status    = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an AWS Web Application Firewall (WAF) Access Control List (ACL) is updated.\n\n## Strategy\nThe rule monitors AWS WAF logs `@eventSource:waf*.amazonaws.com` and detects when the `@evt.name` is `UpdateWebACL`.  \n\n## Triage and response\n1. Determine if {{@userIdentity.arn}} is expected to perform the {{@evt.name}} API call on the account: {{@usr.account_id}}.\n2. If the API call was not made legitimately by the user, rotate the user's credentials and investigate what other APIs were successfully accessed."
  name               = "[TBOL] AWS WAF web access control list modified"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "7200"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "waf_webacl_update"
    query           = "source:cloudtrail @eventSource:waf*.amazonaws.com @evt.name:UpdateWebACL -@http.useragent:(\\APN\\/* OR cloudformation.amazonaws.com)"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_ayl-bvz-mwq" {
  case {
    condition = "a > 0"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an EBS encryption is disabled by default. \n\n## Strategy\nMonitor CloudTrail and detect when EBS encryption is disabled by default via the following API call:\n\n* [DisableEbsEncryptionByDefault][1]\n\n## Triage and response\n1. Determine which user in your organization owns the API key that made this API call.\n2. Contact the user and let them know that it is best practice to enable EBS encryption by default.\n3. Re-enable EBS encryption by default.\n\nFor more information about Amazon EBS Encryption, check out the [Amazon EBS Encryption][2] documentation.\n\n[1]: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DisableEbsEncryptionByDefault.html\n[2]: https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html\n\n## Changelog\n18 March 2022 - Rule query and severity updated."
  name               = "[TBOL] AWS EBS default encryption disabled"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@usr.account_id"]
    query           = "source:cloudtrail @eventSource:ec2.amazonaws.com @evt.name:DisableEbsEncryptionByDefault"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_bko-nf0-2gc" {
  case {
    condition = "nacl_created > 0"
    name      = "network ACL/ACL entry created"
    status    = "info"
  }

  case {
    condition = "nacl_deleted > 0"
    name      = "network ACL/ACL entry deleted"
    status    = "info"
  }

  case {
    condition = "nacl_updated > 0"
    name      = "network ACL/ACL entry updated"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an AWS Network Access Control List (NACL) has been created, deleted or modified.\n\n## Strategy\nThis rule lets you monitor CloudTrail and detect when an AWS NACL has been created, deleted or modified with one of the following API calls:\n* [CreateNetworkAcl][1] \n* [CreateNetworkAclEntry][2] \n* [DeleteNetworkAcl][3] \n* [DeleteNetworkAclEntry][4] \n* [ReplaceNetworkAclEntry][5] \n* [ReplaceNetworkAclAssociation][6]\n\n## Triage and response\n1. Determine if the usr with arn: {{@userIdentity.arn}} should have used the API call: {{@evt.name}}.\n2. Contact the user and see if this API call was made by the user.\n3. If the API call was not made by the user:\n   * Rotate the user credentials and investigate what other API calls.\n   * Determine what other API calls the user made which were not made by the user.\n\n## Changelog\n5 April 2022 - Rule queries, cases and signal message updated.\n\n[1]: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateNetworkAcl.html\n[2]: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_CreateNetworkAclEntry.html\n[3]: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DeleteNetworkAcl.html\n[4]: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_DeleteNetworkAclEntry.html\n[5]: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ReplaceNetworkAclEntry.html\n[6]: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_ReplaceNetworkAclAssociation.html\n"
  name               = "[TBOL] AWS Network Access Control List created or modified"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "86400"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "nacl_created"
    query           = "source:cloudtrail @evt.name:(CreateNetworkAcl OR CreateNetworkAclEntry)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "nacl_deleted"
    query           = "source:cloudtrail @evt.name:(DeleteNetworkAcl OR DeleteNetworkAclEntry)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "nacl_updated"
    query           = "source:cloudtrail @evt.name:(ReplaceNetworkAclEntry OR ReplaceNetworkAclAssociation)"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_c5g-2hq-5bd" {
  case {
    condition = "a > 0"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an attacker is destroying an ECS Cluster\n\n## Strategy\nThis rule lets you monitor this CloudTrail API call to detect if an ECS cluster is deleted:\n\n* [DeleteCluster][1]\n\n## Triage and response\n1. Determine if {{@userIdentity.arm}} should be making a {{@evt.name}} API call.\n2. Contact the user to see if they intended to make this API call.\n3. If the user did not make the API call:\n * Rotate the credentials.\n * Investigate if the same credentials made other unauthorized API calls.\n\n## Changelog\n1 April 2022 - Updated rule query.\n\n[1]: https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_DeleteCluster.html\n"
  name               = "[TBOL] AWS ECS cluster deleted"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    query           = "source:cloudtrail @eventSource:ecs.amazonaws.com @evt.name:DeleteCluster"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_cfy-zuo-ouj" {
  case {
    status = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a user executes a command on an ECS container for the first time. An attacker may use this as a technique to escalate their privileges\nbecause they can run arbitrary commands on behalf of the container with the role and permissions associated with the\ncontainer.\n\n## Strategy\nThis rule lets you monitor this CloudTrail API call to detect if a user is executing a command on an ECS container:\n\n* `ExecuteCommand`\n\n## Triage and response\n1. Investigate the command that the user ({{@userIdentity.arn}}) ran on the container, which is located in the Cloudtrail log at `@requestParameters.container`, if the telemetry exists.\n2. Analyze Cloudtrail logs with {{@userIdentity.arn}} that are within the same time frame as this security signal.\n3. Review any other security signals generated for this container.\n"
  name               = "[TBOL] New user seen executing a command in an ECS task"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "new_value"
    evaluation_window                 = "0"
    keep_alive                        = "0"
    max_signal_duration               = "0"

    new_value_options {
      forget_after       = "28"
      learning_duration  = "1"
      learning_method    = "duration"
      learning_threshold = "0"
    }
  }

  query {
    aggregation     = "new_value"
    group_by_fields = ["@userIdentity.arn"]
    metric          = "@usr.account_id"
    metrics         = ["@usr.account_id"]
    query           = "source:cloudtrail @evt.name:ExecuteCommand @requestParameters.interactive:true"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_cnl-ino-v5o" {
  case {
    condition = "s3_bucket_policy_modified > 0"
    name      = "A S3 bucket policy was modified"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a S3 Bucket policy is modified.\n\n## Strategy\nMonitor CloudTrail and detect when S3 policies are being modified via one of the following API calls:\n* [PutBucketAcl][1]\n* [PutBucketPolicy][2]\n* [PutBucketCors][3]\n* [PutBucketLifecycle][4]\n* [PutBucketReplication][5]\n* [DeleteBucketPolicy][6]\n* [DeleteBucketCors][7]\n* [DeleteBucketReplication][8]\n\n## Triage and response\n1. Determine who the user was who made this API call.\n2. Contact the user and see if this was an API call which was made by the user.\n3. If the API call was not made by the user:\n   * Rotate the user credentials and investigate what other API calls.\n   * Determine what other API calls the user made which were not made by the user.\n\n[1]: https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketAcl.html\n [2]: https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketPolicy.html\n [3]: https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketCors.html\n [4]: https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketLifecycle.html\n [5]: https://docs.aws.amazon.com/AmazonS3/latest/API/API_PutBucketReplication.html\n [6]: https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketPolicy.html\n [7]: https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketCors.html\n [8]: https://docs.aws.amazon.com/AmazonS3/latest/API/API_DeleteBucketReplication.html\n\n## Changelog\n18 March 2022 - Updated signal message, query and severity."
  name               = "[TBOL] S3 bucket policy modified"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "s3_bucket_policy_modified"
    query           = "source:cloudtrail @evt.name:(PutBucketAcl OR PutBucketPolicy OR PutBucketCors OR PutBucketLifecycle OR PutBucketReplication OR DeleteBucketPolicy OR DeleteBucketCors OR DeleteBucketReplication)"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_cpr-vjm-ios" {
  case {
    condition = "sg_opened_by_automated_service > 0"
    name      = "Event generated by automated service"
    status    = "medium"
  }

  case {
    condition = "sg_ftp_port > 0"
    name      = "FTP"
    status    = "high"
  }

  case {
    condition = "sg_ssh_port > 0"
    name      = "SSH"
    status    = "high"
  }

  case {
    condition = "sg_rdp_port > 0"
    name      = "RDP"
    status    = "high"
  }

  case {
    condition = "sg_vnc_port > 0"
    name      = "VNC"
    status    = "high"
  }

  case {
    condition = "sg_dockerd_port > 0"
    name      = "Docker Daemon"
    status    = "high"
  }

  case {
    condition = "sg_winrm_http_port > 0"
    name      = "WinRm HTTP"
    status    = "high"
  }

  case {
    condition = "sg_winrm_https_port > 0"
    name      = "WinRm HTTPS"
    status    = "high"
  }

  case {
    condition = "sg_telnet_port > 0"
    name      = "Telnet"
    status    = "high"
  }

  case {
    condition = "sg_smb_port > 0"
    name      = "SMB"
    status    = "high"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an AWS security group is opened to the world on a port commonly associated with an administrative service.\n\n## Strategy\nMonitor CloudTrail and detect when an AWS security group has been created or modified with one of the following API calls:\n* [`AuthorizeSecurityGroupIngress`][1]\n\nThis rule inspects the `@requestParameters.ipPermissions.items.ipRanges.items.cidrIp` or `@requestParameters.cidrIp` array to determine if either of the strings are contained - `0.0.0.0/0` or `::/0` for the following ports:\n* 21 (FTP)\n* 22 (SSH)\n* 23 (Telnet)\n* 445 (SMB)\n* 2375 (Docker daemon)\n* 3389 (RDP)\n* 5900 (VNC)\n* 5985 (WinRM HTTP)\n* 5986 (WinRM HTTPS)\n\nAdministrative ports that are open to the world are a common target for attackers to gain unauthorized access to resources or data.\n\n**Note:** There is a separate rule to detect AWS [Security Group Open to the World][2].\n\n## Triage and response\n1. Determine if `{{@userIdentity.session_name}}` should have made a `{{@evt.name}}` API call.\n2. If the API call was not made by the user:\n  * Rotate the user credentials.\n  * Determine what other API calls were made by the user.\n  * Investigate VPC flow logs and OS system logs to determine if unauthorized access occurred.\n3. If the API call was made legitimately by the user:\n  * Advise the user to modify the IP range to the company private network or bastion host.\n4. Revert security group configuration back to known good state if required:\n  * Use the `aws-cli` command [`revoke-security-group-ingress`][3] or the [AWS console][4] to remove the rule.\n  * Use the `aws-cli` command [`modify-security-group-rules`][5] or [AWS console][6] to modify the existing rule.\n\n## Changelog\n26 August 2022 - Updated rule query\n\n[1]: https://docs.aws.amazon.com/AWSEC2/latest/APIReference/API_AuthorizeSecurityGroupIngress.html\n[2]: https://docs.datadoghq.com/security_platform/default_rules/aws-security-group-open-to-world/\n[3]: https://docs.aws.amazon.com/cli/latest/reference/ec2/revoke-security-group-ingress.html\n[4]: https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#deleting-security-group-rules\n[5]: https://docs.aws.amazon.com/cli/latest/reference/ec2/modify-security-group-rules.html\n[6]: https://docs.aws.amazon.com/vpc/latest/userguide/VPC_SecurityGroups.html#updating-security-group-rules"
  name               = "[TBOL] Potential administrative port open to the world via AWS security group"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "sg_opened_by_automated_service"
    query           = "source:cloudtrail @eventSource:ec2.amazonaws.com @eventName:AuthorizeSecurityGroupIngress (@requestParameters.ipPermissions.items.ipRanges.items.cidrIp:(\"0.0.0.0/0\" OR \"::/0\") OR @requestParameters.cidrIp:(\"0.0.0.0/0\" OR \"::/0\")) (@requestParameters.fromPort:(21 OR 22 OR 23 OR 445 OR 2375 OR 3389 OR 5900 OR 5985 OR 5986) OR @requestParameters.ipPermissions.items.fromPort:(21 OR 22 OR 3389 OR 5900 OR 2375 OR 5985 OR 5986 OR 23 OR 445) OR @requestParameters.toPort:(21 OR 22 OR 3389 OR 5900 OR 2375 OR 5985 OR 5986 OR 23 OR 445) OR @requestParameters.ipPermissions.items.toPort:(21 OR 22 OR 23 OR 445 OR 2375 OR 3389 OR 5900 OR 5985 OR 5986)) @http.useragent:cloudformation.amazonaws.com @userIdentity.invokedBy:cloudformation.amazonaws.com"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "sg_ftp_port"
    query           = "source:cloudtrail @eventSource:ec2.amazonaws.com @eventName:AuthorizeSecurityGroupIngress (@requestParameters.ipPermissions.items.ipRanges.items.cidrIp:(\"0.0.0.0/0\" OR \"::/0\") OR @requestParameters.cidrIp:(\"0.0.0.0/0\" OR \"::/0\")) (@requestParameters.fromPort:21 OR @requestParameters.ipPermissions.items.fromPort:21 OR @requestParameters.toPort:21 OR @requestParameters.ipPermissions.items.toPort:21)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "sg_ssh_port"
    query           = "source:cloudtrail @eventSource:ec2.amazonaws.com @eventName:AuthorizeSecurityGroupIngress (@requestParameters.ipPermissions.items.ipRanges.items.cidrIp:(\"0.0.0.0/0\" OR \"::/0\") OR @requestParameters.cidrIp:(\"0.0.0.0/0\" OR \"::/0\")) (@requestParameters.fromPort:22 OR @requestParameters.ipPermissions.items.fromPort:22 OR @requestParameters.toPort:22 OR @requestParameters.ipPermissions.items.toPort:22)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "sg_rdp_port"
    query           = "source:cloudtrail @eventSource:ec2.amazonaws.com @eventName:AuthorizeSecurityGroupIngress (@requestParameters.ipPermissions.items.ipRanges.items.cidrIp:(\"0.0.0.0/0\" OR \"::/0\") OR @requestParameters.cidrIp:(\"0.0.0.0/0\" OR \"::/0\")) (@requestParameters.fromPort:3389 OR @requestParameters.ipPermissions.items.fromPort:3389 OR @requestParameters.toPort:3389 OR @requestParameters.ipPermissions.items.toPort:3389)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "sg_vnc_port"
    query           = "source:cloudtrail @eventSource:ec2.amazonaws.com @eventName:AuthorizeSecurityGroupIngress (@requestParameters.ipPermissions.items.ipRanges.items.cidrIp:(\"0.0.0.0/0\" OR \"::/0\") OR @requestParameters.cidrIp:(\"0.0.0.0/0\" OR \"::/0\")) (@requestParameters.fromPort:5900 OR @requestParameters.ipPermissions.items.fromPort:5900 OR @requestParameters.toPort:5900 OR @requestParameters.ipPermissions.items.toPort:5900)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "sg_dockerd_port"
    query           = "source:cloudtrail @eventSource:ec2.amazonaws.com @eventName:AuthorizeSecurityGroupIngress (@requestParameters.ipPermissions.items.ipRanges.items.cidrIp:(\"0.0.0.0/0\" OR \"::/0\") OR @requestParameters.cidrIp:(\"0.0.0.0/0\" OR \"::/0\")) (@requestParameters.fromPort:2375 OR @requestParameters.ipPermissions.items.fromPort:2375 OR @requestParameters.toPort:2375 OR @requestParameters.ipPermissions.items.toPort:2375)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "sg_winrm_http_port"
    query           = "source:cloudtrail @eventSource:ec2.amazonaws.com @eventName:AuthorizeSecurityGroupIngress (@requestParameters.ipPermissions.items.ipRanges.items.cidrIp:(\"0.0.0.0/0\" OR \"::/0\") OR @requestParameters.cidrIp:(\"0.0.0.0/0\" OR \"::/0\")) (@requestParameters.fromPort:5985 OR @requestParameters.ipPermissions.items.fromPort:5985 OR @requestParameters.toPort:5985 OR @requestParameters.ipPermissions.items.toPort:5985)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "sg_winrm_https_port"
    query           = "source:cloudtrail @eventSource:ec2.amazonaws.com @eventName:AuthorizeSecurityGroupIngress (@requestParameters.ipPermissions.items.ipRanges.items.cidrIp:(\"0.0.0.0/0\" OR \"::/0\") OR @requestParameters.cidrIp:(\"0.0.0.0/0\" OR \"::/0\")) (@requestParameters.fromPort:5986 OR @requestParameters.ipPermissions.items.fromPort:5986 OR @requestParameters.toPort:5986 OR @requestParameters.ipPermissions.items.toPort:5986)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "sg_telnet_port"
    query           = "source:cloudtrail @eventSource:ec2.amazonaws.com @eventName:AuthorizeSecurityGroupIngress (@requestParameters.ipPermissions.items.ipRanges.items.cidrIp:(\"0.0.0.0/0\" OR \"::/0\") OR @requestParameters.cidrIp:(\"0.0.0.0/0\" OR \"::/0\")) (@requestParameters.fromPort:23 OR @requestParameters.ipPermissions.items.fromPort:23 OR @requestParameters.toPort:23 OR @requestParameters.ipPermissions.items.toPort:23)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "sg_smb_port"
    query           = "source:cloudtrail @eventSource:ec2.amazonaws.com @eventName:AuthorizeSecurityGroupIngress (@requestParameters.ipPermissions.items.ipRanges.items.cidrIp:(\"0.0.0.0/0\" OR \"::/0\") OR @requestParameters.cidrIp:(\"0.0.0.0/0\" OR \"::/0\")) (@requestParameters.fromPort:445 OR @requestParameters.ipPermissions.items.fromPort:445 OR @requestParameters.toPort:445 OR @requestParameters.ipPermissions.items.toPort:445)"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_d4h-jdg-s1i" {
  case {
    condition = "group_policy_modified > 0"
    name      = "group policy changed"
    status    = "info"
  }

  case {
    condition = "role_policy_modified > 0"
    name      = "role policy changed"
    status    = "info"
  }

  case {
    condition = "user_policy_modified > 0"
    name      = "user policy changed"
    status    = "info"
  }

  case {
    condition = "account_policy_modified > 0"
    name      = "account policy changed"
    status    = "info"
  }

  case {
    condition = "policy_version_modified > 0"
    name      = "policy version changed"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect a change to an AWS IAM Policy.\n\n## Strategy\nThis rule lets you monitor CloudTrail and detect when any event pertaining to an AWS IAM policy is detected with one of the following API calls:\n\n* [DeleteGroupPolicy][1]\n* [DeleteRolePolicy][16]\n* [DeleteUserPolicy][2]\n* [PutGroupPolicy][3]\n* [PutRolePolicy][4]\n* [PutUserPolicy][5]\n* [CreatePolicy][6]\n* [DeletePolicy][7]\n* [SetPolicyVersion][17]\n* [CreatePolicyVersion][8]\n* [DeletePolicyVersion][9]\n* [AttachRolePolicy][10]\n* [DetachRolePolicy][11]\n* [AttachUserPolicy][12]\n* [DetachUserPolicy][13]\n* [AttachGroupPolicy][14]\n* [DetachGroupPolicy][15]\n\n## Triage and response\n1. Review the IAM Policy change and ensure it does not negatively impact your risk in relation to authentication or authorization controls.\n2. If risk is increased, contact the individual that used the arn: {{@userIdentity.arn}} and determine if {{@evt.name}} API calls were made by them.\n\n## Changelog\n5 April 2022 - Rule modified and signal message updated.\n\n[1]: https://docs.aws.amazon.com/IAM/latest/APIReference/API_DeleteGroupPolicy.html\n[2]: https://docs.aws.amazon.com/IAM/latest/APIReference/API_DeleteUserPolicy.html\n[3]: https://docs.aws.amazon.com/IAM/latest/APIReference/API_PutGroupPolicy.html\n[4]: https://docs.aws.amazon.com/IAM/latest/APIReference/API_PutRolePolicy.html\n[5]: https://docs.aws.amazon.com/IAM/latest/APIReference/API_PutUserPolicy.html\n[6]: https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreatePolicy.html\n[7]: https://docs.aws.amazon.com/IAM/latest/APIReference/API_DeletePolicy.html\n[8]: https://docs.aws.amazon.com/IAM/latest/APIReference/API_CreatePolicyVersion.html\n[9]: https://docs.aws.amazon.com/IAM/latest/APIReference/API_DeletePolicyVersion.html\n[10]: https://docs.aws.amazon.com/IAM/latest/APIReference/API_AttachRolePolicy.html\n[11]: https://docs.aws.amazon.com/IAM/latest/APIReference/API_DetachRolePolicy.html\n[12]: https://docs.aws.amazon.com/IAM/latest/APIReference/API_AttachUserPolicy.html\n[13]: https://docs.aws.amazon.com/IAM/latest/APIReference/API_DetachUserPolicy.html\n[14]: https://docs.aws.amazon.com/IAM/latest/APIReference/API_AttachGroupPolicy.html\n[15]: https://docs.aws.amazon.com/IAM/latest/APIReference/API_DetachGroupPolicy.html\n[16]: https://docs.aws.amazon.com/IAM/latest/APIReference/API_DeleteRolePolicy.html\n[17]: https://docs.aws.amazon.com/IAM/latest/APIReference/API_SetDefaultPolicyVersion.html\n"
  name               = "[TBOL] AWS IAM policy changed"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "900"
    keep_alive                        = "3600"
    max_signal_duration               = "86400"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "group_policy_modified"
    query           = "source:cloudtrail -@level:Error @evt.name:(DeleteGroupPolicy OR PutGroupPolicy OR AttachGroupPolicy OR DetachGroupPolicy)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "role_policy_modified"
    query           = "source:cloudtrail -@level:Error @evt.name:(DeleteRolePolicy OR PutRolePolicy OR AttachRolePolicy OR DetachRolePolicy)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "user_policy_modified"
    query           = "source:cloudtrail -@level:Error @evt.name:(DeleteUserPolicy OR PutUserPolicy OR AttachUserPolicy OR DetachUserPolicy)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "account_policy_modified"
    query           = "source:cloudtrail -@level:Error @evt.name:(CreatePolicy OR DeletePolicy)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "policy_version_modified"
    query           = "source:cloudtrail -@level:Error @evt.name:(SetPolicyVersion OR CreatePolicyVersion OR DeletePolicyVersion)"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_dyx-edd-j6j" {
  case {
    condition = "waf_webacl_deletion > 0"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an AWS Web Application Firewall (WAF) Access Control List (ACL) is deleted.\n\n## Strategy\nThe rule monitors AWS WAF logs `@eventSource:waf*.amazonaws.com` and detects when the `@evt.name` is `DeleteWebACL`.  \n\n## Triage and response\n1. Determine if {{@userIdentity.arn}} is expected to perform the {{@evt.name}} API call on the account: {{@usr.account_id}}.\n2. If the API call was not made by the user, rotate the user credentials and investigate what other APIs were successfully accessed."
  name               = "[TBOL] AWS WAF web access control list deleted"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "7200"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "waf_webacl_deletion"
    query           = "source:cloudtrail @eventSource:waf*.amazonaws.com @evt.name:DeleteWebACL -@http.useragent:\\APN\\/*"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_eie-jms-uck" {
  case {
    condition = "a > 0"
    status    = "high"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an AMI is made public.\n\n## Strategy\nThis rule lets you monitor these CloudTrail API calls to detect if an AMI is made public.\n\n* [ModifyImageAttribute][1]\n\nThis rule inspects the `@requestParameters.launchPermission.add.items.group` array to determine if the string `all` is contained. This is the indicator which means the image is made public.\n\n## Triage and response\n1. Determine if the AMI (`@requestParameters.imageId`) should be made public using CloudTrail logs.\n2. Investigate the following ARN (`{{@userIdentity.arn}}`) that made the AMI public.\n3. Contact the user to see if they intended to make the image public.\n4. If the user did not make the API call:\n * Rotate the credentials.\n * Investigate if the same credentials made other unauthorized API calls.\n\n[1]: https://docs.aws.amazon.com/cli/latest/reference/ec2/modify-image-attribute.html#examples"
  name               = "[TBOL] AWS AMI Made Public"

  options {
    decrease_criticality_based_on_env = "true"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    query           = "source:cloudtrail @evt.name:ModifyImageAttribute @requestParameters.launchPermission.add.items.group:\"all\""
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_ejd-8zb-hlg" {
  case {
    condition = "a > 0"
    status    = "high"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an S3 bucket policy is made public.\n\n## Strategy\nThis rule lets you monitor these CloudTrail API calls to detect when an AWS bucket is made public:\n\n* [PutBucketAcl][1]\n\nThis rule inspects the `@requestParameters.AccessControlPolicy.AccessControlList.Grant.Grantee.URI` array to determine if either of the strings are contained:\n* `http://acs.amazonaws.com/groups/global/AuthenticatedUsers`\n* `http://acs.amazonaws.com/groups/global/AllUsers`\n\nA match of either of these string indicates the S3 bucket policy is made public.\n\n## Triage and response\n1. Determine if {{@userIdentity.arn}} is expected to perform the {{@evt.name}} API call.\n2. Contact the principal owner and see if this was an API call that was made by the user.\n3. If the API call was not made by the user, rotate the user credentials and investigate what other APIs were successfully accessed.\n   * Rotate the credentials.\n   * Investigate if the same credentials made other unauthorized API calls.\n\n## Changelog\n7 April 2022 - Update rule and signal message.\n\n[1]: https://awscli.amazonaws.com/v2/documentation/api/latest/reference/s3api/put-bucket-acl.html\n"
  name               = "[TBOL] AWS S3 Bucket ACL Made Public"

  options {
    decrease_criticality_based_on_env = "true"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@requestParameters.bucketName"]
    query           = "source:cloudtrail @evt.name:PutBucketAcl -@level:Error @requestParameters.AccessControlPolicy.AccessControlList.Grant.Grantee.URI:(\"http://acs.amazonaws.com/groups/global/AuthenticatedUsers\"  OR \"http://acs.amazonaws.com/groups/global/AllUsers\")"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_fy6-d8t-lkk" {
  case {
    condition = "rds_snapshot_shared > 0"
    name      = "Snapshot was shared"
    status    = "high"
  }

  case {
    condition = "rds_snapshot_made_public > 0"
    name      = "Snapshot was made public"
    status    = "high"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect a user attempting to exfiltrate data from an RDS Snapshot.\n\n## Strategy\nThis rule lets you monitor the [ModifyDBClusterSnapshotAttribute][1] CloudTrail API calls to detect when an RDS snapshot is made public.\n\nThis rule also inspects the:\n * `@requestParameters.valuesToAdd` array to determine if the string `all` is contained. This is the indicator which means the RDS snapshot is made public.\n * `@requestParameters.attributeName` array to determine if the string `restore` is contained. This is the indicator which means the RDS snapshot was shared with a new or unkown AWS Account.\n\n## Triage and response\n1. Confirm if the user: `{{@userIdentity.arn}}`intended to make the RDS snaphsot public.\n2. If the user did not make the API call:\n * Rotate the credentials.\n * Investigate if the same credentials made other unauthorized API calls.\n\n[1]: https://awscli.amazonaws.com/v2/documentation/api/latest/reference/rds/modify-db-cluster-snapshot-attribute.html#modify-db-cluster-snapshot-attribute\n"
  name               = "[TBOL] Possible RDS Snapshot Exfiltration"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "rds_snapshot_made_public"
    query           = "source:cloudtrail @eventSource:rds.amazonaws.com @evt.name:ModifyDBClusterSnapshotAttribute @requestParameters.valuesToAdd:all"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "rds_snapshot_shared"
    query           = "source:cloudtrail @eventSource:rds.amazonaws.com @evt.name:(ModifyDBClusterSnapshotAttribute OR ModifyDBSnapshotAttribute) @requestParameters.attributeName:restore -@http.useragent:(*AWS_Lambda* OR *AWS_ECS_FARGATE* OR backup.amazonaws.com)"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_h1n-eys-e2s" {
  case {
    condition = "a > 0"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a user deleted a database cluster in RDS.\n\n## Strategy\nThis rule lets you monitor this CloudTrail API call to detect if an attacker is deleting a RDS cluster:\n\n* [DeleteDBCluster][1]\n\n## Triage and response\n1. Determine if the API call: {{@evt.name}} should have occurred.\n2. If it shouldn't have been made:\n   * Contact the user: {{@userIdentity.arn}} and see if they made the API call.\n3. If the API call was not made by the user:\n   * Rotate the user credentials.\n   * Determine what other API calls were made with the old credentials that were not made by the user.\n\n## Changelog\n6 April 2022 - Updated rule and signal message.\n\n[1]: https://docs.aws.amazon.com/cli/latest/reference/rds/delete-db-cluster.html\n"
  name               = "[TBOL] AWS RDS Cluster deleted"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    query           = "source:cloudtrail -@level:Error @evt.name:DeleteDBCluster"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_h3h-4nc-gsi" {
  case {
    condition = "aws_config_deleted_or_stopped > 0"
    name      = "Deleted/Stopped"
    status    = "high"
  }

  case {
    condition = "aws_config_modified > 0"
    name      = "Modified"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an attacker is trying to evade defenses by disabling or modifying AWS Config.\n\n## Strategy\nThis rule lets you monitor these AWS Config API calls per [CIS-AWS-4.9: Ensure a log metric filter and alarm exist for AWS Config configuration changes][5]:\n\n* [StopConfigurationRecorder][1] \n* [DeleteDeliveryChannel][2] \n* [PutDeliveryChannel][3]\n* [PutConfigurationRecorder][4]\n\n## Triage and response\n1. Determine which if {{@userIdentity.arn}} should have done a {{@evt.name}} to AWS Config.\n2. If the user did not make the API call:\n   * Rotate the credentials.\n   * Investigate if the same credentials made other unauthorized API calls.\n\n[1]: https://docs.aws.amazon.com/config/latest/APIReference/API_StopConfigurationRecorder.html\n[2]: https://docs.aws.amazon.com/config/latest/APIReference/API_DeleteDeliveryChannel.html\n[3]: https://docs.aws.amazon.com/config/latest/APIReference/API_PutDeliveryChannel.html\n[4]: https://docs.aws.amazon.com/config/latest/APIReference/API_PutConfigurationRecorder.html\n[5]: https://docs.aws.amazon.com/config/latest/developerguide/operational-best-practices-for-cis_aws_benchmark_level_2.html\n\n## Changelog\n1 April 2022 - Updated rule and signal message."
  name               = "[TBOL] AWS Config modified"

  options {
    decrease_criticality_based_on_env = "true"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "aws_config_deleted_or_stopped"
    query           = "source:cloudtrail @evt.name:(StopConfigurationRecorder OR DeleteDeliveryChannel)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@userIdentity.arn"]
    name            = "aws_config_modified"
    query           = "source:cloudtrail @evt.name:(PutDeliveryChannel OR PutConfigurationRecorder)"
  }

  type = "log_detection"
}

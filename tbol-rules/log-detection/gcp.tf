resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_0m8-cos-gkh" {
  case {
    condition = "a > 0"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a change to a GCP Pub/Sub Subscription has been made. This could stop audit logs from being sent to Datadog.\n\n## Strategy\nMonitor GCP admin activity audit logs to determine when any of the following methods are invoked:\n\n* `google.pubsub.v1.Subscriber.UpdateSubscription`\n* `google.pubsub.v1.Subscriber.DeleteSubscription`\n\n## Triage and response\n1. Review the subscribtion and ensure it is properly configured.\n"
  name               = "[TBOL] GCP Pub/Sub Subscriber modified"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "300"
    max_signal_duration               = "300"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@usr.id", "@data.protoPayload.resourceName"]
    query           = "source:gcp.pubsub.subscription @evt.name:(google.pubsub.v1.Subscriber.UpdateSubscription OR google.pubsub.v1.Subscriber.DeleteSubscription)"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_7v4-msr-mfc" {
  case {
    condition = "a > 0"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a GCP Pub/Sub Subscribtion has been deleted. This could stop audit logs from being sent to Datadog.\n\n## Strategy\nMonitor GCP admin activity audit logs to determine when the following method is invoked:\n\n* `google.pubsub.v1.Publisher.DeleteTopic`\n\n## Triage and response\n1. Review the subscribtion and ensure it is properly configured.\n"
  name               = "[TBOL] GCP Pub/Sub topic deleted"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "300"
    max_signal_duration               = "300"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@usr.id", "@data.protoPayload.resourceName"]
    query           = "source:gcp.pubsub.topic @evt.name:google.pubsub.v1.Publisher.DeleteTopic"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_amz-gjz-nmr" {
  case {
    condition = "failed_attempt > 999"
    name      = "greater than 999 failed attempts"
    status    = "high"
  }

  case {
    condition = "failed_attempt > 100"
    name      = "greater than 100 failed attempts"
    status    = "medium"
  }

  case {
    condition = "failed_attempt > 10"
    name      = "greater than 10 failed attempts"
    status    = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when unauthorized activity by a user is detected in GCP.\n\n## Strategy\nMonitor GCP logs and detect when a user account makes an API request and the request returns the status code equal to `7` within the log attribute `@data.protoPayload.status.code`. The status code `7` indicates the user account did not have permission to make the API call.\n\n## Triage and response\n1. Investigate the user:`{{@usr.id}}` that made the unauthorized calls and confirm if there is a misconfiguration in IAM permissions or if an attacker compromised the user account.\n2. If unauthorized, revoke access of compromised user account and rotate credentials.\n\n## Changelog\n22 June 2022 - Updated query, rule case and triage."
  name               = "[TBOL] GCP unauthorized user activity"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "300"
    max_signal_duration               = "300"
  }

  query {
    aggregation     = "cardinality"
    distinct_fields = ["@evt.name"]
    group_by_fields = ["@usr.id"]
    name            = "failed_attempt"
    query           = "source:gcp.* @data.protoPayload.status.code:7 -@usr.id:(*gserviceaccount.com OR *google.com)"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_dky-1fr-g5f" {
  case {
    name   = "access_denied"
    status = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a GCP service account (`@usr.id:*.iam.gserviceaccount.com`) exhibits access denied behavior that deviates from normal.\n\n## Strategy \nInspect the GCP Service Account (`@usr.id:*.iam.gserviceaccount.com`) for errors (`@data.protoPayload.status.code:7`) caused by denied permissions (`@evt.outcome`). The anomaly detection will baseline each service account and then generate a security signal when a service account deviates from their baseline. \n\n## Triage and response\nInvestigate the logs and determine whether or not the GCP Service Account {{@usr.id}} is compromised."
  name               = "[TBOL] Access denied for GCP Service Account"

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
    name            = "access_denied"
    query           = "source:gcp.* @data.protoPayload.status.code:7 @usr.id:(*gserviceaccount.com OR *google.com)"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_dwh-ann-sge" {
  case {
    condition = "a > 0"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect a change to the IAM policy. \n\n## Strategy\nThis rule lets you monitor GCP admin activity audit logs to determine when the `SetIamPolicy` method is invoked. \n\n## Triage and response\n1. Review the log and inspect the policy deltas (`@data.protoPayload.serviceData.policyDelta.bindingDeltas`) and ensure none of the actions are `REMOVE`.\n"
  name               = "[TBOL] GCP IAM policy modified"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "300"
    max_signal_duration               = "300"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@usr.id"]
    query           = "source:gcp.project @evt.name:SetIamPolicy"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_e0y-c4j-j80" {
  case {
    condition = "a > 0"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a firewall rule is created or modified. \n\n## Strategy\nThis rule lets you monitor GCP GCE activity audit logs to determine if a firewall is being adjusted by showing you when any of the following methods are invoked:\n\n* `beta.compute.routes.insert`\n* `beta.compute.routes.patch`\n\n## Triage and response\n1. Veirify that the GCP route is configured properly and that the user intended to modify the firewall.\n"
  name               = "[TBOL] GCP GCE network route created or modified"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "300"
    max_signal_duration               = "300"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["project_id", "@data.protoPayload.resourceName", "@usr.id"]
    query           = "source:gcp.gce.route @evt.name:(beta.compute.routes.insert OR beta.compute.routes.patch)"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_fbr-8lq-3mg" {
  case {
    condition = "a > 0"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a change to a GCP logging sink has been made. This could stop audit logs from being sent to Datadog.\n\n## Strategy\nMonitor GCP admin activity audit logs to determine when any of the following methods are invoked:\n\n* `google.logging.v2.ConfigServiceV2.UpdateSink`\n* `google.logging.v2.ConfigServiceV2.DeleteSink`\n\n## Triage and response\n1. Review the sink and ensure the sink is properly configured.\n"
  name               = "[TBOL] GCP logging sink modified"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "300"
    max_signal_duration               = "300"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@usr.id", "@data.protoPayload.resourceName"]
    query           = "source:gcp.project @evt.name:(google.logging.v2.ConfigServiceV2.UpdateSink OR google.logging.v2.ConfigServiceV2.DeleteSink)"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_gen-p3g-cpm" {
  case {
    condition = "a > 0"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a firewall rule is created, modified or deleted. \n\n## Strategy\nMonitor GCP GCE activity audit logs to determine when any of the following methods are invoked:\n\n* `v1.compute.firewalls.delete`\n* `v1.compute.firewalls.insert`\n* `v1.compute.firewalls.patch` \n\n## Triage and response\n1. Review the log and role and ensure the permissions are scoped properly.\n2. Review the users associated with the role and ensure they should have the permissions attached to the role.\n"
  name               = "[TBOL] GCP GCE Firewall rule modified"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "300"
    max_signal_duration               = "300"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["project_id", "@data.protoPayload.resourceOriginalState.name", "@usr.id"]
    query           = "source:gcp.gce.firewall.rule @evt.name:(v1.compute.firewalls.delete OR v1.compute.firewalls.insert OR v1.compute.firewalls.patch)"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_gv1-hbt-n5c" {
  case {
    condition = "a > 0"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a new service account key is created.  An attacker could use this key as a backdoor to your account. \n\n## Strategy\nThis rule lets you monitor GCP admin activity audit logs to detect the creation of a service account key. \n\n## Triage and response\n1. Contact the user who created the service account key to ensure they're managing the key securely.\n"
  name               = "[TBOL] GCP service account key created"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "300"
    max_signal_duration               = "300"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@usr.id"]
    query           = "source:gcp.service.account @evt.name:google.iam.admin.v1.CreateServiceAccountKey"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_hrs-j54-jtn" {
  case {
    status = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a GCP service account is compromised.\n\n## Strategy \nInspect the GCP Admin Activity Logs (`@data.logName:*%2Factivity`) and filter for only GCP Service Accounts (`@usr.id:*.iam.gserviceaccount.com`). Count the unique number of GCP API calls (`@evt.name`) which are being made for each service account (`@usr.id`). The anomaly detection will baseline each service account and then generate a security signal when a service account deviates from their baseline. \n\nTo read more about GCP Audit Logs, you can read our blog post [here][1].\n\n## Triage and response\nInvestigate the logs and determine whether or not the GCP Service Account is compromised.\n\n[1]: https://www.datadoghq.com/blog/monitoring-gcp-audit-logs/"
  name               = "[TBOL] GCP service account accessing anomalous number of GCP APIs"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "anomaly_detection"
    evaluation_window                 = "1800"
    keep_alive                        = "1800"
    max_signal_duration               = "1800"
  }

  query {
    aggregation     = "cardinality"
    distinct_fields = ["@evt.name"]
    group_by_fields = ["@usr.id"]
    query           = "source:gcp* @data.logName:*%2Factivity @usr.id:*.iam.gserviceaccount.com"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_j2y-fev-6ni" {
  case {
    condition = "a > 0"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a Cloud SQL DB has been modified.\n\n## Strategy\nThis rule lets you monitor GCP Cloud SQL admin activity audit logs to determine when one of the following methods are invoked:\n\n* `cloudsql.instances.create`\n* `cloudsql.instances.create`\n* `cloudsql.users.update`\n\n## Triage and response\n1. Review the Cloud SQL DB and ensure it is configured properly with the correct permissions.\n"
  name               = "[TBOL] GCP Cloud SQL database modified"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "300"
    max_signal_duration               = "300"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["project_id", "database_id", "@usr.id"]
    query           = "source:gcp.cloudsql.database @evt.name:(cloudsql.instances.create OR cloudsql.instances.create OR cloudsql.users.create OR cloudsql.users.update)"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_j95-gco-0my" {
  case {
    condition = "a > 0"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when permissions have changed on a GCS Bucket.\n\n## Strategy\nMonitor GCS bucket admin activity audit logs to determine the following method is invoked:\n\n* `storage.setIamPermissions`\n\n## Triage and response\n1. Review the bucket permissions and ensure they are not overly permissive.\n\n## Changelog\n5 Septermber 2022 - Updated rule query"
  name               = "[TBOL] GCP Bucket permissions modified"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "300"
    max_signal_duration               = "300"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["project_id", "bucket_name", "@usr.id"]
    query           = "source:gcp.gcs.bucket @evt.name:storage.setIamPermissions -@evt.outcome:ERROR"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_kwb-kpp-tdm" {
  case {
    condition = "failed_attempt > 999"
    name      = "greater than 999 failed attempts"
    status    = "high"
  }

  case {
    condition = "failed_attempt > 100"
    name      = "greater than 100 failed attempts"
    status    = "medium"
  }

  case {
    condition = "failed_attempt > 10"
    name      = "greater than 10 failed attempts"
    status    = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when there is unauthorized activity by a service account in GCP.\n\n## Strategy\nMonitor GCP logs and detect when a service account makes an API request and the request returns the status code equal to `7` within the log attribute `@data.protoPayload.status.code`. The status code `7` indicates the service account did not have permission to make the API call.\n\n## Triage and response\n1. Investigate the service account:`{{@usr.id}}` that made the unauthorized calls and confirm if there is a misconfiguration in IAM permissions or if an attacker compromised the service account.\n2. If unauthorized, revoke access of compromised service account and rotate credentials.\n\n## Changelog\n22 June 2022 - Updated query, rule case and triage."
  name               = "[TBOL] GCP unauthorized service account activity"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "300"
    max_signal_duration               = "300"
  }

  query {
    aggregation     = "cardinality"
    distinct_fields = ["@evt.name"]
    group_by_fields = ["@usr.id"]
    name            = "failed_attempt"
    query           = "source:gcp.* @data.protoPayload.status.code:7 @usr.id:(*gserviceaccount.com OR *google.com)"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_rv8-ulh-eno" {
  case {
    condition = "a > 0"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a VPC network is created. \n\n## Strategy\nThis rule lets you monitor GCP GCE activity audit logs to determine when the following method is invoked to create a new VPC network:\n\n* `beta.compute.networks.insert`\n\n## Triage and response\n1. Review the VPC network.\n"
  name               = "[TBOL] GCP GCE VPC network modified"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "300"
    max_signal_duration               = "300"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["project_id", "@data.protoPayload.resourceName", "@usr.id"]
    query           = "source:gcp.gce.route @evt.name:beta.compute.networks.insert"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_uvj-fqf-n7k" {
  case {
    condition = "get_object > 0"
    name      = "get_object"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect unauthenticated access to an object in a GCS bucket (`bucket_name`).\n\n## Strategy \nMonitor GCS bucket (`bucket_name`) for get requests(`@evt.name:storage.objects.get`) made by unauthenticated users (`@usr.id`).\n\n## Triage and response\nInvestigate the logs and determine whether or not the accessed bucket: {{bucket_name}} should be accessible to unauthenticated users."
  name               = "[TBOL] GCP Bucket Contents Downloaded Without Authentication"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "300"
    max_signal_duration               = "300"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["project_id", "bucket_name"]
    name            = "get_object"
    query           = "source:gcp.gcs.bucket -@usr.id:* @evt.name:storage.objects.get status:info"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_w8o-qxu-kt2" {
  case {
    condition = "a > 0"
    status    = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a service account lists out GCS Buckets.\n\n## Strategy\nThis rule lets you monitor GCS bucket admin activity audit logs to determine when a service account invokes the following method:\n\n* `storage.buckets.list`\n\n## Triage and response\n1. Determine whether this service account should be making list bucket calls.\n * If the account was compromised, secure the account and investigate how it was compromised and if the account made other unauthorized calls.\n * If the owner of the service account intended to make the `ListBuckets` API call, consider whether this API call is needed. It could cause a security issue for the application to know the name of the bucket it needs to access. If it's not needed, modify this rule's filter to stop generating signals for this specific service account.\n"
  name               = "[TBOL] GCP Bucket enumerated"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "300"
    max_signal_duration               = "300"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["project_id", "@usr.id"]
    query           = "source:gcp.gcs.bucket @evt.name:storage.buckets.list @usr.id:*gserviceaccount.com"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_y7o-gtx-wyx" {
  case {
    condition = "a > 0"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an administrative change to a GCS Bucket has been made. This could change the retention policy or bucket lock. For more information, see the [GCS Bucket Lock docs][1].\n\n## Strategy\nThis rule lets you monitor GCS bucket admin activity audit logs to determine if a bucket has been updated with the following method:\n\n* `storage.buckets.update`\n\n## Triage and response\n1. Review the bucket to ensure that it is properly configured.\n\n[1]: https://cloud.google.com/storage/docs/bucket-lock\n"
  name               = "[TBOL] GCP Bucket modified"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "300"
    max_signal_duration               = "300"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["project_id", "bucket_name", "@usr.id"]
    query           = "source:gcp.gcs.bucket @evt.name:storage.buckets.update"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_yyj-c9i-j3b" {
  case {
    condition = "a > 0"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a new service account is created.\n\n## Strategy\nThis rule lets you monitor GCP admin activity audit logs to determine when a service account is created. \n\n## Triage and response\n1. Contact the user who created the service account and ensure that the account is needed and that the role is scoped properly.\n"
  name               = "[TBOL] GCP service account created"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "300"
    max_signal_duration               = "300"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@usr.id"]
    query           = "source:gcp.service.account @evt.name:google.iam.admin.v1.CreateServiceAccount"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_zkq-dwh-gqr" {
  case {
    condition = "a > 0"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a custom role is created or modified. \n\n## Strategy\nMonitor GCP IAM activity audit logs to determine when any of the following methods are invoked:\n\n* `google.iam.admin.v1.CreateRole`\n* `google.iam.admin.v1.UpdateRole` \n\n## Triage and response\n1. Review the log and role and ensure the permissions are scoped properly.\n2. Review the users associated with the role and ensure they should have the permissions attached to the role.\n"
  name               = "[TBOL] GCP IAM custom role created or modified"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "300"
    max_signal_duration               = "300"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@usr.id"]
    query           = "source:gcp.iam.role @evt.name:(google.iam.admin.v1.CreateRole OR google.iam.admin.v1.UpdateRole)"
  }

  type = "log_detection"
}

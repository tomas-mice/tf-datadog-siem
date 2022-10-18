resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_7ne-bmi-2ga" {
  case {
    condition = "domain_resolve_to_metadata_ip > 0"
    status    = "high"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a requested domain resolves to the AWS Metadata IP (169.254.169.254).\n\n## Strategy\nInspect the Route 53 logs and determine if the response data for a DNS request matches the AWS Metadata IP (169.254.169.254). This could indicate an attacker is attempting to steal your credentials from the AWS metadata service.\n\n## Triage and response\n1. Determine which instance is associated with the DNS request.\n2. Determine whether the domain name which was requested (`dns.question.name`) should be permitted. If not, conduct an investigation and determine what requested the domain and determine if the AWS metadata credentials were accessed by an attacker.\n\n## Changelog\n- 19 May 2022 - Updated rule query.\n- 5 Jun 2022 - Updated rule query."
  name               = "[TBOL] EC2 instance resolved a suspicious AWS metadata DNS query"

  options {
    decrease_criticality_based_on_env = "true"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["instance-id"]
    name            = "domain_resolve_to_metadata_ip"
    query           = "source:route53 @answers.Rdata:169.254.169.254 -@route53_edge_location:* -@dns.question.name:instance-data*"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_aje-dl2-eyp" {
  case {
    condition = "a > 0"
    status    = "high"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a host is potentially infected with a cryptominer.\n\n## Strategy\nThis rule compares the `@network.client.ip` standard attribute to a curated list of cryptomining pools.\n\n## Triage and response\n1. Determine if the `{{host}}` host should be contacting a cryptomining pool.\n2. If not, begin your company's IR process.\n\n**Note** You can use the signal sidepanel to assist with the initial investigation by looking at CPU utilization and processes to identify unauthorized activity.\n\n## Changelog\n- 8 April 2022 - Initial beta release to select organizations.\n- 13 April 2022 - Added additional filters for specific ports to reduce false positives. \n- 26 April 2022 - Removed restrictedToOrgs settings, launching rule to all of production.\n"
  name               = "[TBOL] Potential cryptomining detected through IP callback"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "86400"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["host"]
    query           = "@threat_intel.results.category:cryptomining @network.destination.port:(6641 OR 6642 OR 9000 OR 9999 OR 14433 OR 10191 OR 20009) host:*"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_bhj-7p9-6pd" {
  case {
    condition = "versioning_suspended > 0 \u0026\u0026 mfadelete_disabled > 0"
    name      = "mfaDelete and Versioning are Disabled/Suspended"
    status    = "medium"
  }

  case {
    condition = "mfadelete_disabled > 0 || versioning_suspended > 0"
    name      = "mfaDelete or versioning are disabled"
    status    = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect if versioning or MFA delete was disabled within an AWS S3 bucket's Lifecycle configuration.\n\n## Strategy\nThis rule has two separate queries. The first query determines if `@requestParameters.VersioningConfiguration.MfaDelete` is set to `Disabled`. The second query determines if `@requestParameters.VersioningConfiguration.Status` is set to `Suspended`. For generating a signal, there are two cases. Case one generates a `Medium` signal if query one AND two return `true`. Case two will generate a `Low` signal if query one OR two returns `true`.\n\n**NOTE**: Versioning cannot be disabled permanently; only suspended until turned back on, once it has been enabled on a bucket.\n\n## Triage \u0026 Response\n1. Determine if `{{@evt.name}}` should have occurred on the `{{@requestParameters.bucketName}}` by `username:` `{{@userIdentity.sessionContext.sessionIssuer.userName}}`, `accountId:` `{{@usr.account_id}}` of `type:` `{{@userIdentity.assumed_role}}`.\n"
  name               = "[TBOL] An AWS S3 bucket mfaDelete is disabled"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "7200"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@aws.s3.bucket"]
    name            = "mfadelete_disabled"
    query           = "-status:error @eventSource:s3.amazonaws.com @evt.name:PutBucketVersioning @requestParameters.VersioningConfiguration.MfaDelete:Disabled"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@requestParameters.bucketName"]
    name            = "versioning_suspended"
    query           = "-status:error @eventSource:s3.amazonaws.com @evt.name:PutBucketVersioning @requestParameters.VersioningConfiguration.Status:Suspended"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_cz7-rde-azs" {
  case {
    condition = "pwd_cmd_in_details > 0"
    name      = "PWD/CMD request in http.url_details.queryString key"
    status    = "low"
  }

  case {
    condition = "pwd_cmd_in_url > 0"
    name      = "PWD/CMD request in http.url key"
    status    = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nThis rule detects attempted post-exploitation activity of [CVE-2022-22965][1] with an HTTP GET parameter.\n\n## Strategy\nThis rule looks for `@http.url_details.path` = <RANDOM_FILE_NAME>.jsp, `@http.url_details.queryString.pwd` = `*`, and `@http.url_details.queryString.cmd` = <RANDOM_CMD_EXECUTION>. If found, it indicates web shell activity observed with successful Spring RCE exploitation. \n\n## Triage and response\nCheck your host to see if the {{@http.url_details.queryString.cmd}} command ran successfully. If so,\n   * Refer to your company's Incident Response process since this is detection post-exploitation activity.\n   * Refer to the vendor's [advisory][2] for remediation of this Remote Code Execution (RCE) vulnerability.\n\n## Changelog\n- 06 June 2022 - The severity has been lowered due to rule fidelity on just log telemetry.\n- 31 March 2022 - Rule added in response to [CVE-2022-22965][1]\n\n[1]: https://tanzu.vmware.com/security/cve-2022-22965\n[2]: https://spring.io/blog/2022/03/31/spring-framework-rce-early-announcement"
  name               = "[TBOL] Spring RCE post-exploitation activity attempted"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "7200"
  }

  query {
    aggregation = "count"
    name        = "pwd_cmd_in_details"
    query       = "@http.url_details.path:*.jsp @http.url_details.queryString.pwd:* @http.url_details.queryString.cmd:* @http.method:GET @http.status_code:200"
  }

  query {
    aggregation = "count"
    name        = "pwd_cmd_in_url"
    query       = "@http.url:*cmd* @http.url:*pwd* @http.method:GET @http.url:*.jsp* @http.status_code:200"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_eis-x4y-wds" {
  case {
    condition = "multiple_200s_and_unique_paths > 10"
    name      = "scan detected returning several 200s"
    status    = "low"
  }

  case {
    condition = "multiple_400s_and_unique_paths > 10"
    name      = "scan detected returning several 400s"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a web application is being scanned. This will identify attacker IP addresses who are not trying to hide their attempt to attack your system. More advanced hackers will use an inconspicuous `@http.useragent`. \n\n## Strategy\nInspect the user agent in the HTTP headers to determine if an IP is scanning your application using an HTTP header from [darkqusar][1]'s [gist][2]. The detection does this using 2 cases:\n* Case 1: The scanner is accessing several unique `@http.url_details.path`s and receiving `@http.status_code`s in the range of `200 TO 299`\n* Case 2: The scanner is accessing several unique `@http.url_details.path`s and receiving `@http.status_code`s in the range of `400 TO 499`\n\n## Triage and response\n1. Determine if this IP: {{@network.client.ip}} is making authenticated requests to the application.\n2. Check if these authentication requests are successful.\n   * If they are successful, change the status of the signal to `UNDER REVIEW` and begin your company's incident response plan.\n   * If they are not successful, `ARCHIVE` the signal.\n\n**NOTE:** Your organization should tune out user agents that are valid and triggering this signal. To do this, see our [Fine-tune security signals to reduce noise][3] blog.\n\n## Changelog\n4 April 2022 - Update rule cases and signal message.\n\n[1]: https://gist.github.com/darkquasar\n[2]: https://gist.github.com/darkquasar/84fb2cec6cc1668795bd97c02302d380\n[3]: https://www.datadoghq.com/blog/writing-datadog-security-detection-rules/#fine-tune-security-signals-to-reduce-noise\n"
  name               = "[TBOL] AWS ELB HTTP requests from security scanner"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "86400"
  }

  query {
    aggregation     = "cardinality"
    distinct_fields = ["@http.url_details.path"]
    group_by_fields = ["@network.client.ip"]
    name            = "multiple_400s_and_unique_paths"
    query           = "source:elb @http.status_code:[400 TO 499] @http.useragent:(*burp* OR *burpcollaborator.net* OR *qualys* OR *nexpose* OR *OpenVAS* OR *Nikto* OR *Meterpreter* OR *IceWeasel* OR *DirB* OR *Comodo* OR *Tripwire* OR *Retina* OR *MBSA* OR *ImmuniWeb* OR *Netsparker* OR *Acunetix* OR *Intruder* OR *nmap* OR *CVE* OR *base64* OR *eval* OR *javascript* OR *alert*)"
  }

  query {
    aggregation     = "cardinality"
    distinct_fields = ["@http.url_details.path"]
    group_by_fields = ["@network.client.ip"]
    name            = "multiple_200s_and_unique_paths"
    query           = "source:elb @http.status_code:[200 TO 299] @http.useragent:(*burp* OR *burpcollaborator.net* OR *qualys* OR *nexpose* OR *OpenVAS* OR *Nikto* OR *Meterpreter* OR *IceWeasel* OR *DirB* OR *Comodo* OR *Tripwire* OR *Retina* OR *MBSA* OR *ImmuniWeb* OR *Netsparker* OR *Acunetix* OR *Intruder* OR *nmap* OR *CVE* OR *base64* OR *eval* OR *javascript* OR *alert*)"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_eqm-tnt-vud" {
  case {
    condition = "a > 0"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect if an AWS S3 lifecycle expiration policy is set to disabled in your CloudTrail logs.\n\n## Strategy\nCheck if `@requestParameters.LifecycleConfiguration.Rule.Expiration.Days`, `@requestParameters.LifecycleConfiguration.Status:Disabled` and `@evt.name:PutBucketLifecycle` fields are present in your S3 Lifecycle configuration log. If these fields are present together, a bucket's lifecycle configuration has been turned off.\n\n## Triage \u0026 Response\n1. Determine if `{{@evt.name}}` should have occurred on the `{{@requestParameters.bucketName}}` by `username:` `{{@userIdentity.sessionContext.sessionIssuer.userName}}`, `accountId:` `{{@usr.account_id}}` of `type:` `{{@userIdentity.assumed_role}}`.\n2. If the `{{@requestParameters.bucketName}}` should not be disabled, escalate to engineering so they can re-enable it.\n"
  name               = "[TBOL] An AWS S3 bucket lifecycle expiration policy was set to disabled"

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
    query           = "-status:error @eventSource:s3.amazonaws.com @evt.name:PutBucketLifecycle @requestParameters.LifecycleConfiguration.Rule.Expiration:* @requestParameters.LifecycleConfiguration.Rule.Status:Disabled"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_jpv-myn-rwi" {
  case {
    condition = "suspicious_tld > 0"
    name      = "TLD"
    status    = "medium"
  }

  case {
    condition = "suspicious_ddns > 0"
    name      = "Dynamic DNS"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a requested domain has a suspicious TLD.\n\n## Strategy\nInspect the Route 53 logs and determine if the TLD of the DNS question (`@dns.question.name`) matches one of the top 5 TLDs on [Spamhaus's Most Abused Top Level Domains list][1].\n\n## Triage and response\n1. Determine which instance is associated with the DNS request.\n2. Determine whether the domain name which was requested (`dns.question.name`) should be permitted. If not, conduct an investigation and determine what requested the domain and determine if the AWS metadata credentials were accessed by an attacker.\n\n[1]: https://www.spamhaus.org/statistics/tlds/\n"
  name               = "[TBOL] EC2 instance requested a suspicious domain"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["instance-id"]
    name            = "suspicious_tld"
    query           = "@dns.question.name:(*.fit. OR *.work. OR *.webcam. OR *.loan. OR *.cf.) -@route53_edge_location:*"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["instance-id"]
    name            = "suspicious_ddns"
    query           = "@dns.question.name:(*.no-ip. OR *.hopto.org OR *.myftp.org OR *.us.to OR *.myvpc.com OR *.dlinkddns.com OR *.myftp.biz) -@route53_edge_location:*"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_t4n-omq-65q" {
  case {
    condition = "policy_deleted > 0"
    name      = "lifecycle policy deleted"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "# WARNING: Rule is being deprecated on 10 April 2022\n\n## Goal\nDetect if an entire AWS S3 Lifecycle configuration is deleted from a bucket.\n\n## Strategy\nUsing the `@evt.name`, the Datadog standard attribute that shows the API call, determine if a `DeleteBucketLifecycle` call occurred.\n\n## Triage \u0026 Response\n1. Determine if `{{@evt.name}}` should have occurred on the `{{@requestParameters.bucketName}}` by `username:` `{{@usr.name}}`, `accountId:` `{{@usr.id}}` of `type:` `{{@userIdentity.type}}`.\n2. If the `{{@evt.name}}` API call accidentally occurred, restore the configuration to the `{{@requestParameters.bucketName}}`. Otherwise, investigate further.\n\n## Changelog\n08 Mar 2022 - Deprecating rule. If a policy is deleted, the data remains forever."
  name               = "[TBOL] [DEPRECATED] An AWS S3 bucket lifecycle policy was deleted"

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
    name            = "policy_deleted"
    query           = "-status:error @eventSource:s3.amazonaws.com @evt.name:DeleteBucketLifecycle"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_xbd-q5y-fxq" {
  case {
    condition = "a > 0"
    status    = "high"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a stolen laptop has been connected to the network.\n\n## Strategy\nUsing the Datadog [Lookup Processor](https://docs.datadoghq.com/logs/processing/processors/?tab=ui#lookup-processor) you can maintain a blocklist of MAC addresses.\nWhen a MAC address connects to the network, the @threat.stolen_laptop attribute is set to `true`.\nThis threat detection rule queries for `@threat.stolen_laptop:true` and generates a security signal. \n\n## Triage and response\nEnter your triage and response process for when a stolen laptop has connected to your network to help users responding to the security signal quickly triage and respond to the signal. \n"
  name               = "[TBOL] TEMPLATE - Stolen Laptop Connected to Network"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@network.client.mac"]
    query           = "@threat.stolen_laptop:true @network.client.mac:*"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_yss-hhc-6sh" {
  case {
    condition = "file_deny > 10"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect and identify users accessing files they do not have permission to access.\n\n## Strategy\nMonitor AWS FSx logs and detect more than 10 occurrences where `@evt.id` is equal to `4656` and `@Event.System.Keywords` is equal to `0x8010000000000000`. \n\n## Triage \u0026 Response\n1. Inspect the log and determine if the user should be accessing the file: `{{@ObjectName}}`.\n2. If access is not legitimate, investigate user `({{@usr.id}})` activity. \n"
  name               = "[TBOL] AWS FSx Excessive File Denied"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "cardinality"
    distinct_fields = ["@ObjectName"]
    group_by_fields = ["@usr.id"]
    name            = "file_deny"
    query           = "source:aws.fsx @evt.id:4656 @Event.System.Keywords:0x8010000000000000"
  }

  type = "log_detection"
}

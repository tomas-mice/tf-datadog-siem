resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_eki-wo2-e4c" {
  case {
    condition = "a > 0"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an EC2 instance receives an inbound network connection from TOR.\n\n## Strategy\nThis rule lets you monitor this [GuardDuty integration][1] finding:\n\n* [UnauthorizedAccess:EC2/TorIPCaller][2]\n\n\n## Triage and response\n1. This is typically an informative signal. However, if this instance should not be publicly available, you should review the security group for this instance. \n\n[1]: https://docs.datadoghq.com/integrations/amazon_guardduty/\n[2]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_unauthorized.html#unauthorized7\n"
  name               = "[TBOL] AWS EC2 instance inbound connections from TOR"

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
    query           = "source:guardduty @evt.name:(UnauthorizedAccess\\:EC2\\/TorIPCaller)"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_eko-vps-wml" {
  case {
    condition = "a > 0"
    status    = "high"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an EC2 instance makes a DNS request and resolves to the AWS metadata IP address (169.254.169.254).\n\n## Strategy\nThis rule lets you monitor this [GuardDuty integration][1] finding:\n\n* [UnauthorizedAccess:EC2/MetadataDNSRebind][2]\n\n\n## Triage and response\n1. Determine which process made the DNS request. The DNS request can be found in the samples.\n2. Ensure the process is not a victim of an SSRF attack to steal the AWS EC2 Instance profile's STS credentials.  \n2. If the STS credentials are compromised:\n   * Review the AWS [documentation][3] on revoking the session.\n\n[1]: https://docs.datadoghq.com/integrations/amazon_guardduty/\n[2]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_unauthorized.html#ec2-metadatadnsrebind\n[3]: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html\n"
  name               = "[TBOL] AWS EC2 Instance Victim to Metadata DNS Rebind Attack"

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
    query           = "source:guardduty @evt.name:(UnauthorizedAccess\\:EC2\\/MetadataDNSRebind)"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_en0-bqa-tbm" {
  case {
    condition = "a > 0"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an EC2 instance is compromised and sending spam emails.\n\n## Strategy\nThis rule lets you monitor this [GuardDuty integration][1] finding:\n\n* [Backdoor:EC2/Spambot][2]\n\n\n## Triage and response\n1. Determine if the EC2 should be sending out email over port 25. \n2. If the instance is compromised:\n   * Review the AWS [documentation][3] on remediating a compromised EC2 instance.\n\n[1]: https://docs.datadoghq.com/integrations/amazon_guardduty/\n[2]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_backdoor.html#backdoor6\n[3]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-ec2\n"
  name               = "[TBOL] AWS EC2 instance Sending spam emails"

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
    query           = "source:guardduty @evt.name:(Backdoor\\:EC2\\/Spambot)"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_evw-8dz-gvy" {
  case {
    condition = "a > 0"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an EC2 instance makes an outbound network connection to a malcious IP address.\n\n## Strategy\nThis rule lets you monitor this [GuardDuty integration][1] finding:\n\n* [UnauthorizedAccess:EC2/MaliciousIPCaller.Custom][2]\n\n## Triage and response\n1. Determine which IP address triggered the signal. This can be found in the sample.\n2. If the instance is compromised:\n   * Review the AWS [documentation][3] on remediating a compromised EC2 instance.\n\n[1]: https://docs.datadoghq.com/integrations/amazon_guardduty/\n[2]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_unauthorized.html#unauthorized5\n[3]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-creds\n"
  name               = "[TBOL] AWS EC2 instance communicating with malicious IP"

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
    query           = "source:guardduty @evt.name:(UnauthorizedAccess\\:EC2\\/MaliciousIPCaller.Custom)"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_hfz-chd-xi7" {
  case {
    condition = "a > 0"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an AWS IAM user is attempting to escalate permissions.\n\n## Strategy\nThis rule lets you monitor this [GuardDuty integration][1] finding:\n\n* [PrivilegeEscalation:IAMUser/AdministrativePermissions][2]\n\n## Triage and response\n1. Determine which user triggered the signal. This can be found in the signal.\n2. Determine if the user's credentials are compromised.  \n3. If the user's credentials are compromised:\n  * Review the AWS [documentation][3] on remediating compromised AWS credentials.\n\n[1]: https://docs.datadoghq.com/integrations/amazon_guardduty/\n[2]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_privilegeescalation.html#privilegeescalation1\n[5]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-creds\n"
  name               = "[TBOL] AWS IAM user escalating privileges"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@detail.resource.accessKeyDetails.userName"]
    query           = "source:guardduty @evt.name:(PrivilegeEscalation\\:IAMUser\\/AdministrativePermissions)"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_jkx-wjj-akm" {
  case {
    condition = "a > 0"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an EC2 instance is communicating over an unusual port.\n\n## Strategy\nThis rule lets you monitor this [GuardDuty integration][1] finding:\n\n* [Behavior:EC2/NetworkPortUnusual][2]\n\n\n## Triage and response\n1. Determine which port triggered the signal. This can be found in the samples.\n2. If the instance is compromised:\n   * Review the AWS [documentation][3] on remediating a compromised EC2 instance.\n\n[1]: https://docs.datadoghq.com/integrations/amazon_guardduty/\n[2]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_behavior.html#behavior3\n[3]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-ec2\n"
  name               = "[TBOL] AWS EC2 instance communicating over unusual port"

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
    query           = "source:guardduty @evt.name:(Behavior\\:EC2\\/NetworkPortUnusual)"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_jyj-1nd-wib" {
  case {
    condition = "actor > 0"
    name      = "Actor"
    status    = "high"
  }

  case {
    condition = "target > 0"
    name      = "Target"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect Brute Force Attacks\n\n## Strategy\nLeverage GuardDuty and detect when an attacker is performing a brute force attack. The following are GuardDuty findings trigger this signal:\n\n* [UnauthorizedAccess:EC2/SSHBruteForce][1]\n* [UnauthorizedAccess:EC2/RDPBruteForce][2]\n\n\n## Triage and response\n1. Inspect the role of the EC2 instance in the attack. Find the role in the signal name - either `ACTOR` or `TARGET`.\n   * If you are the `TARGET` and the instance is available on the internet, expect to see IPs scanning your systems.\n   * If you are the `TARGET` and the instance is **not** available on the internet, this means a host on your internal network is scanning your EC2 instance. Open an investigation.\n   * If you are the `ACTOR`, this means that your instance is performing brute force attacks on other systems. Open an investigation.\n\n[1]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_unauthorized.html#unauthorized9\n[2]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_unauthorized.html#unauthorized10\n"
  name               = "[TBOL] AWS EC2 instance involved in brute force attack"

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
    name            = "actor"
    query           = "source:guardduty @evt.name:(UnauthorizedAccess\\:EC2\\/SSHBruteForce OR UnauthorizedAccess\\:EC2\\/RDPBruteForce OR Impact\\:EC2\\/WinRMBruteForce) @detail.service.resourceRole:ACTOR"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["instance-id"]
    name            = "target"
    query           = "source:guardduty @evt.name:(UnauthorizedAccess\\:EC2\\/SSHBruteForce OR UnauthorizedAccess\\:EC2\\/RDPBruteForce OR Impact\\:EC2\\/WinRMBruteForce) @detail.service.resourceRole:TARGET"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_ltj-kml-efi" {
  case {
    condition = "a > 0"
    status    = "high"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an EC2 instance makes an outbound network connection from TOR.\n\n## Strategy\nThis rule lets you monitor this [GuardDuty integration][1] finding:\n\n* [UnauthorizedAccess:EC2/TorClient][2]\n\n\n## Triage and response\n1. Determine if the EC2 instance should be making requests to TOR. \n2. If the instance is compromised:\n   * Review the AWS [documentation][3] on remediating a compromised EC2 instance. \n\n[1]: https://docs.datadoghq.com/integrations/amazon_guardduty/\n[2]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_unauthorized.html#unauthorized13\n[3]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-ec2\n"
  name               = "[TBOL] AWS EC2 instance outbound connections to TOR"

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
    query           = "source:guardduty @evt.name:(UnauthorizedAccess\\:EC2\\/TorClient)"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_ouh-as2-sqs" {
  case {
    condition = "a > 0"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an EC2 instance network traffic volume is unusual.\n\n## Strategy\nThis rule lets you monitor this [GuardDuty integration][1] finding:\n\n* [Behavior:EC2/TrafficVolumeUnusual][2]\n\n## Triage and response\n1. Determine which port triggered the signal. This can be found in the samples.\n2. If the instance is compromised:\n   * Review the AWS [documentation][3] on remediating a compromised EC2 instance.\n\n[1]: https://docs.datadoghq.com/integrations/amazon_guardduty/\n[2]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_behavior.html#behavior4\n[3]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-ec2\n"
  name               = "[TBOL] AWS EC2 instance network traffic volume unusual"

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
    query           = "source:guardduty @evt.name:(Behavior\\:EC2\\/TrafficVolumeUnusual)"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_pgq-fut-owh" {
  case {
    condition = "a > 0"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an AWS IAM user makes API requests with hacking tools.\n\n## Strategy\nThis rule lets you monitor these [GuardDuty integration][1] findings:\n\n* [PenTest:IAMUser/KaliLinux][2]\n* [PenTest:IAMUser/ParrotLinux][3]\n* [PenTest:IAMUser/PentooLinux][4]\n\n## Triage and response\n1. Determine which user triggered the signal. This can be found in the signal.\n2. Determine if the user's credentials are compromised.  \n3. If the user's credentials are compromised:\n  * Review the AWS [documentation][5] on remediating compromised AWS credentials.\n\n[1]: https://docs.datadoghq.com/integrations/amazon_guardduty/\n[2]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_pentest.html#pentest1\n[3]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_pentest.html#pentest2\n[4]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_pentest.html#pentest3\n[5]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-creds\n"
  name               = "[TBOL] AWS IAM user making API requests with hacking tools"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@detail.resource.accessKeyDetails.userName"]
    query           = "source:guardduty @evt.name:(PenTest\\:IAMUser\\/KaliLinux OR PenTest\\:IAMUser\\/ParrotLinux OR PenTest\\:IAMUser\\/PentooLinux)"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_pie-glg-ecl" {
  case {
    condition = "a > 0"
    status    = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an AWS IAM user is changing sensitive configurations and has no prior history of invoking these APIs.\n\n## Strategy\nThis rule lets you monitor these [GuardDuty integration][1] findings:\n\n* [Stealth:IAMUser/S3ServerAccessLoggingDisabled][2]\n* [Stealth:IAMUser/PasswordPolicyChange][3]\n* [Stealth:IAMUser/CloudTrailLoggingDisabled][4]\n* [Stealth:IAMUser/LoggingConfigurationModified][5]\n\n## Triage and response\n1. Determine which user triggered the signal. This can be found in the signal.\n2. Determine if the user's credentials are compromised.  \n3. If the user's credentials are compromised:\n  * Review the AWS [documentation][6] on remediating compromised AWS credentials.\n\n[1]: https://docs.datadoghq.com/integrations/amazon_guardduty/\n[2]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_stealth.html#stealth4\n[3]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_stealth.html#stealth1\n[4]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_stealth.html#stealth2\n[5]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_stealth.html#stealth3\n[6]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-creds\n"
  name               = "[TBOL] AWS IAM user changing sensitive configurations"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@detail.resource.accessKeyDetails.userName"]
    query           = "source:guardduty @evt.name:(Stealth\\:IAMUser\\/S3ServerAccessLoggingDisabled OR Stealth\\:IAMUser\\/PasswordPolicyChange OR Stealth\\:IAMUser\\/CloudTrailLoggingDisabled OR Stealth\\:IAMUser\\/LoggingConfigurationModified)"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_pxx-boy-c1q" {
  case {
    condition = "a > 0"
    status    = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an AWS IAM user disables [S3 Block Public Access][1]\n\n## Strategy\nThis rule lets you monitor this [GuardDuty integration][2] finding:\n\n* [Policy:IAMUser/S3BlockPublicAccessDisabled][3]\n\n## Triage and response\n1. Determine which user triggered the signal. This can be found in the signal.\n2. Contact the user and determine why the user disabled the S3 Block Access feature.   \n3. Re-enable S3 Block Public Access.\n\n[1]: https://docs.aws.amazon.com/AmazonS3/latest/dev/access-control-block-public-access.html\n[2]: https://docs.datadoghq.com/integrations/amazon_guardduty/\n[3]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_policy.html#policy2\n"
  name               = "[TBOL] AWS IAM user disabled S3 Block Public Access"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@detail.resource.accessKeyDetails.userName"]
    query           = "source:guardduty @evt.name:(Policy\\:IAMUser\\/S3BlockPublicAccessDisabled)"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_ql8-yfo-kyd" {
  case {
    condition = "a > 0"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an AWS IAM user login is suspicious.\n\n## Strategy\nThis rule lets you monitor these [GuardDuty integration][1] findings:\n\n* [UnauthorizedAccess:IAMUser/ConsoleLoginSuccess.B][2]\n* [UnauthorizedAccess:IAMUser/ConsoleLogin][3]\n\n## Triage and response\n1. Determine which user triggered the signal. This can be found in the signal.\n2. Determine if the user's credentials are compromised.  \n3. If the user's credentials are compromised:\n  * Review the AWS [documentation][4] on remediating compromised AWS credentials.\n\n[1]: https://docs.datadoghq.com/integrations/amazon_guardduty/\n[2]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_unauthorized.html#unauthorized4\n[3]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_unauthorized.html#unauthorized12\n[4]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-creds\n"
  name               = "[TBOL] AWS IAM user suspicious login"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@detail.resource.accessKeyDetails.userName"]
    query           = "source:guardduty @evt.name:(UnauthorizedAccess\\:IAMUser\\/ConsoleLoginSuccess.B OR UnauthorizedAccess\\:IAMUser\\/ConsoleLogin)"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_vyh-rlf-jos" {
  case {
    condition = "a > 0"
    status    = "high"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an EC2 instance is communicating with a cryptocurrency server\n\n## Strategy\nThis rule lets you leverage GuardDuty to detect when an EC2 instance has made a DNS request or is communicating with an IP that is associated with cryptocurrency operations. The following GuardDuty Findings trigger this signal:\n\n* [CryptoCurrency:EC2/BitcoinTool.B!DNS][1]\n* [CryptoCurrency:EC2/BitcoinTool.B][2]\n\n\n## Triage and response\n1. Determine which domain name or IP address triggered the signal. This can be found in the samples. \n2. If the domain or IP address should not have been requested, open a security investigation, and determine which process requested the domain name or IP address.\n\n[1]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_crypto.html#crypto3\n[2]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_crypto.html#crypto4\n"
  name               = "[TBOL] AWS EC2 instance communicating with a cryptocurrency server"

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
    query           = "source:guardduty @evt.name:(CryptoCurrency\\:EC2\\/BitcoinTool.B\\!DNS OR CryptoCurrency\\:EC2\\/BitcoinTool.B)"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_w0e-lau-m16" {
  case {
    condition = "a > 0"
    status    = "high"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an EC2 instance is participating in a Denial of Service (DoS) attack.\n\n## Strategy\nThis rule lets you monitor these [GuardDuty integration][1] findings:\n\n* [Backdoor:EC2/DenialOfService.Tcp][2]\n* [Backdoor:EC2/DenialOfService.Udp][3]\n* [Backdoor:EC2/DenialOfService.Dns][4]\n* [Backdoor:EC2/DenialOfService.UdpOnTcpPorts][5]\n* [Backdoor:EC2/DenialOfService.UnusualProtocol][6]\n\n\n## Triage and response\n1. Determine if the EC2 instance is compromised and participating in a DoS attack.\n2. If the instance is compromised:\n   * Review the AWS [documentation][7] on remediating a compromised EC2 instance.\n\n[1]: https://docs.datadoghq.com/integrations/amazon_guardduty/\n[2]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_backdoor.html#backdoor8\n[3]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_backdoor.html#backdoor9\n[4]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_backdoor.html#backdoor10\n[5]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_backdoor.html#backdoor11\n[6]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_backdoor.html#backdoor12\n[7]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-ec2\n"
  name               = "[TBOL] AWS EC2 instance participating in a DoS attack"

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
    query           = "source:guardduty @evt.name:(Backdoor\\:EC2\\/DenialOfService.Tcp OR Backdoor\\:EC2\\/DenialOfService.Udp OR Backdoor\\:EC2\\/DenialOfService.Dns OR Backdoor\\:EC2\\/DenialOfService.UdpOnTcpPorts OR Backdoor\\:EC2\\/DenialOfService.UnusualProtocol)"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_wtk-gal-suh" {
  case {
    condition = "a > 0"
    status    = "high"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an EC2 instance is communicating with a malicious server.\n\n## Strategy\nThis rule lets you monitor these [GuardDuty integration][1] findings:\n\n* [Backdoor:EC2/C\u0026CActivity.B!DNS][2]\n* [Trojan:EC2/BlackholeTraffic][3]\n* [Trojan:EC2/DropPoint][4]\n* [Trojan:EC2/BlackholeTraffic!DNS][5]\n* [Trojan:EC2/DriveBySourceTraffic!DNS][6]\n* [Trojan:EC2/DropPoint!DNS][7]\n* [Trojan:EC2/DGADomainRequest.B][8]\n* [Trojan:EC2/DGADomainRequest.C!DNS][9]\n* [Trojan:EC2/DNSDataExfiltration][10]\n* [Trojan:EC2/PhishingDomainRequest!DNS][11]\n\n\n## Triage and response\n1. Determine which domain name or IP address triggered the signal. This can be found in the samples.\n2. If the instance is compromised:\n   * Review the AWS [documentation][12] on remediating a compromised EC2 instance.\n\n[1]: https://docs.datadoghq.com/integrations/amazon_guardduty/\n[2]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_backdoor.html#backdoor6\n[3]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_trojan.html#trojan4\n[4]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_trojan.html#trojan5\n[5]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_trojan.html#trojan6\n[6]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_trojan.html#trojan7\n[7]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_trojan.html#trojan8\n[8]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_trojan.html#trojan9\n[9]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_trojan.html#trojan95\n[10]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_trojan.html#trojan10\n[11]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_trojan.html#trojan11\n[12]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-ec2\n"
  name               = "[TBOL] AWS EC2 instance communicated with a malicious server"

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
    query           = "source:guardduty @evt.name:(Trojan\\:EC2\\/BlackholeTraffic OR Trojan\\:EC2\\/DropPoint OR Trojan\\:EC2\\/BlackholeTraffic\\!DNS OR Trojan\\:EC2\\/DriveBySourceTraffic\\!DNS OR Trojan\\:EC2\\/DropPoint\\!DNS OR Trojan\\:EC2\\/DGADomainRequest.B OR Trojan\\:EC2\\/DGADomainRequest.C\\!DNS OR Backdoor\\:EC2\\/C\u0026CActivity.B\\!DNS OR Trojan\\:EC2\\/PhishingDomainRequest\\!DNS)"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_xjx-hrx-njd" {
  case {
    condition = "a > 0"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an EC2 instance is being probed by a scanner.\n\n## Strategy\nThis rule lets you monitor these [GuardDuty integration][1] findings:\n\n* [Recon:EC2/PortProbeUnprotectedPort][2]\n* [Recon:EC2/PortProbeEMRUnprotectedPort][3]\n\n\n## Triage and response\n1. This is typically an informative signal. However, if this instance should not be publicly available, you should review the security group for this instance. \n\n[1]: https://docs.datadoghq.com/integrations/amazon_guardduty/\n[2]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_recon.html#recon6\n[3]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_recon.html#PortProbeEMRUnprotectedPort\n"
  name               = "[TBOL] AWS EC2 instance probed by scanner"

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
    query           = "source:guardduty @evt.name:(Recon\\:EC2\\/PortProbeUnprotectedPort OR Recon\\:EC2\\/PortProbeEMRUnprotectedPort)"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_yw9-88w-sbx" {
  case {
    condition = "a > 0"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an EC2 instance is conducting a port scan.\n\n## Strategy\nThis rule lets you monitor this [GuardDuty integration][1] finding:\n\n* [Recon:EC2/Portscan][2]\n\n\n## Triage and response\n1. Determine why traffic from the EC2 instance appears to be conducting a port scan.\n2. If the instance is compromised:\n   * Review the AWS [documentation][3] on remediating a compromised EC2 instance.\n \n[1]: https://docs.datadoghq.com/integrations/amazon_guardduty/\n[2]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_recon.html#recon5\n[3]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-ec2\n"
  name               = "[TBOL] AWS EC2 instance conducting a port scan"

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
    query           = "source:guardduty @evt.name:(Recon\\:EC2\\/Portscan)"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_ba3-6c3-79r" {
  case {
    condition = "a > 0"
    status    = "high"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an EC2 instance is being used as a TOR relay.\n\n## Strategy\nThis rule lets you monitor this [GuardDuty integration][1] finding:\n\n* [UnauthorizedAccess:EC2/TorRelay][2]\n\n\n## Triage and response\n1. Determine if the EC2 instance should be uses as a TOR relay. \n2. If the instance is compromised:\n   * Review the AWS [documentation][3] on remediating a compromised EC2 instance. \n\n[1]: https://docs.datadoghq.com/integrations/amazon_guardduty/\n[2]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_unauthorized.html#unauthorized14\n[3]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-ec2\n"
  name               = "[TBOL] AWS EC2 instance connecting to TOR as a relay"

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
    query           = "source:guardduty @evt.name:(UnauthorizedAccess\\:EC2\\/TorRelay)"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_bet-a7i-vf5" {
  case {
    condition = "a > 0"
    status    = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when the AWS root user credentials are used.\n\n## Strategy\nThis rule lets you monitor this [GuardDuty integration][1] finding:\n\n* [Policy:IAMUser/RootCredentialUsage][2]\n\n## Triage and response\n1. Determine whether the root account activity was legitimate. \n * Review the sample for context. \n * Review CloudTrail logs for a full investigation. \n3. If the root user's credentials are compromised:\n * Review the AWS [documentation][3] on remediating compromised AWS credentials.\n\n**[Root Account Best Practices][4]**\n\n[1]: https://docs.datadoghq.com/integrations/amazon_guardduty/\n[2]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_policy.html#policy1\n[3]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-creds\n[4]: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html\n"
  name               = "[TBOL] AWS Root credential activity"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation = "count"
    query       = "source:guardduty @evt.name:(Policy\\:IAMUser\\/RootCredentialUsage)"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_bfh-ruu-ryu" {
  case {
    condition = "a > 0"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an AWS IAM user makes API requests from a malicious IP.\n\n## Strategy\nThis rule lets you monitor these [GuardDuty integration][1] findings:\n\n* [Recon:IAMUser/TorIPCaller][2]\n* [Recon:IAMUser/MaliciousIPCaller.Custom][3]\n* [Recon:IAMUser/MaliciousIPCaller][4]\n* [UnauthorizedAccess:IAMUser/MaliciousIPCaller][5]\n\n## Triage and response\n1. Determine which user triggered the signal. This can be found in the signal.\n2. Determine if the user's credentials are compromised.  \n3. If the user's credentials are compromised:\n  * Review the AWS [documentation][6] on remediating compromised AWS credentials.\n\n[1]: https://docs.datadoghq.com/integrations/amazon_guardduty/\n[2]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_recon.html#recon1\n[3]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_recon.html#recon2\n[4]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_recon.html#recon3\n[5]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_unauthorized.html#unauthorized5\n[6]: https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_remediate.html#compromised-creds\n"
  name               = "[TBOL] AWS IAM user requests from malicious IP"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@detail.resource.accessKeyDetails.userName"]
    query           = "source:guardduty @evt.name:(Recon\\:IAMUser\\/TorIPCaller OR Recon\\:IAMUser\\/MaliciousIPCaller.Custom OR Recon\\:IAMUser\\/MaliciousIPCaller OR UnauthorizedAccess\\:IAMUser\\/MaliciousIPCaller)"
  }

  type = "log_detection"
}

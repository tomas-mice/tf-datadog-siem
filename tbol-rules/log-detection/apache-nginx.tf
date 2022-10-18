resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_2n0-dgi-qpo" {
  case {
    condition = "a > 0"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a web application is being scanned. This will identify attacker IP addresses who are not trying to hide their attempt to attack your system. More advanced hackers will use an inconspicuous user agent. \n\n## Strategy\nInspect the user agent in the HTTP headers to determine if an IP is scanning your application and generate an `INFO` signal. \n\n## Triage and response\n1. Determine if this IP is making authenticated requests to the application.\n2. If the IP is making authenticated requests to the application:\n * Investigate the HTTP logs and determine if the user is attacking your application.\n\nThe HTTP headers in the query are from [darkqusar][1]'s [gist][2] \n\n[1]: https://gist.github.com/darkquasar\n[2]: https://gist.github.com/darkquasar/84fb2cec6cc1668795bd97c02302d380\n"
  name               = "[TBOL] NGINX HTTP requests from security scanner"

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
    query           = "source:nginx @http.useragent:(*burp* OR *burpcollaborator.net* OR *qualys* OR *nexpose* OR *OpenVAS* OR *Nikto* OR *Meterpreter* OR *IceWeasel* OR *DirB* OR *Comodo* OR *Tripwire* OR *Retina* OR *MBSA* OR *ImmuniWeb* OR *Netsparker* OR *Acunetix* OR *Intruder* OR *nmap* OR *CVE* OR *base64* OR *eval* OR *javascript* OR *alert*)"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_f7b-bl6-woe" {
  case {
    condition = "a > 0"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a web application is being scanned. This will identify attacker IP addresses who are not trying to hide their attempt to attack your system. More advanced hackers will use an inconspicuous user agent. \n\n## Strategy\nInspect the user agent in the HTTP headers to determine if an IP is scanning your application and generate an `INFO` signal. \n\n## Triage and response\n1. Determine if this IP is making authenticated requests to the application.\n2. If the IP is making authenticated requests to the application:\n * Investigate the HTTP logs and determine if the user is attacking your application.\n\nThe HTTP headers in the query are from [darkqusar][1]'s [gist][2] \n\n[1]: https://gist.github.com/darkquasar\n[2]: https://gist.github.com/darkquasar/84fb2cec6cc1668795bd97c02302d380\n"
  name               = "[TBOL] NGINX ingress controller HTTP requests from security scanner"

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
    query           = "source:nginx-ingress-controller @http.useragent:(*burp* OR *burpcollaborator.net* OR *qualys* OR *nexpose* OR *OpenVAS* OR *Nikto* OR *Meterpreter* OR *IceWeasel* OR *DirB* OR *Comodo* OR *Tripwire* OR *Retina* OR *MBSA* OR *ImmuniWeb* OR *Netsparker* OR *Acunetix* OR *Intruder* OR *nmap* OR *CVE* OR *base64* OR *eval* OR *javascript* OR *alert*)"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_snp-iok-e8d" {
  case {
    condition = "standard_attributes > 0"
    name      = "standard attribute query triggered"
    status    = "medium"
  }

  case {
    condition = "non_standard_attributes > 0"
    name      = "non standard attribute query triggered"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nThis rule detects if your Apache or NGINX web servers are being exploited using the log4j vulnerability. The initial vulnerability was identified as [CVE-2021-44228](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228).\n\n## Strategy\nThis signal evaluated that `Base64` has been detected in the HTTP header fields `user agent` and `referrer` or `referer`.\n\n## Triage and response\n1. Ensure you servers have the most recent version of log4j installed. \n2. If you are not patched, decode the base64 string and look for any successful traffic to the malicious server.\n3. If a connection was successful to the malicious server, begin your company's IR procedures to remediate.\n\nNote: Datadog's `The Monitor` blog has an article published about [\"The Log4j Logshell vulnerability: Overview, detection, and remediation\"](https://www.datadoghq.com/blog/log4j-log4shell-vulnerability-overview-and-remediation/). "
  name               = "[TBOL] Base64 was detected in an http.user_agent or http.referrer"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "7200"
  }

  query {
    aggregation = "count"
    name        = "standard_attributes"
    query       = "source:(apache OR nginx) (@http.referrer:(*jndi\\:ldap*Base64* OR *jndi\\:rmi*Base64* OR *jndi\\:dns*Base64*) OR @http.user_agent:(*jndi\\:ldap*Base64* OR *jndi\\:rmi*Base64* OR *jndi\\:dns*Base64*))"
  }

  query {
    aggregation = "count"
    name        = "non_standard_attributes"
    query       = "source:(apache OR nginx) (@http_referer:(*jndi\\:ldap*Base64* OR *jndi\\:rmi*Base64* OR *jndi\\:dns*Base64*) OR @http_referrer:(*jndi\\:ldap*Base64* OR *jndi\\:rmi*Base64* OR *jndi\\:dns*Base64*) OR @http_user_agent:(*jndi\\:ldap*Base64* OR *jndi\\:rmi*Base64* OR *jndi\\:dns*Base64*))"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_eeu-rue-vgq" {
  case {
    condition = "standard_attributes > 0"
    name      = "standard attribute query triggered"
    status    = "info"
  }

  case {
    condition = "non_standard_attributes > 0"
    name      = "non standard attribute query triggered"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nThis rule detects if your Apache or NGINX web servers are being scanned for the log4j vulnerability. The initial vulnerability was identified as [CVE-2021-44228](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228).\n\n## Strategy\nThis signal evaluated that `jndi:(ldap OR rmi OR dns)` has been detected in the HTTP header fields `user agent` and `referrer` or `referer`.\n\n## Triage and response\n1. Ensure you servers have the most recent version of log4j installed. \n2. Check if the `Base64 was detected in an http.user_agent or http.referrer` rule was also triggered and follow the `Triage and response` steps in that rule.\n\nNote: Datadog's `The Monitor` blog has an article published about [\"The Log4j Logshell vulnerability: Overview, detection, and remediation\"](https://www.datadoghq.com/blog/log4j-log4shell-vulnerability-overview-and-remediation/). "
  name               = "[TBOL] Log4j Scanner detected in user agent or referrer"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "7200"
  }

  query {
    aggregation = "count"
    name        = "standard_attributes"
    query       = "source:(apache OR nginx) (@http.referer:(*jndi\\:ldap* OR *jndi\\:rmi* OR *jndi\\:dns*) OR @http.useragent:(*jndi\\:ldap* OR *jndi\\:rmi* OR *jndi\\:dns*))"
  }

  query {
    aggregation = "count"
    name        = "non_standard_attributes"
    query       = "source:(apache OR nginx) (@http_referrer:(*jndi\\:ldap* OR *jndi\\:rmi* OR *jndi\\:dns*) OR @http_user_agent:(*jndi\\:ldap* OR *jndi\\:rmi* OR *jndi\\:dns*) OR @http.user_agent:(*jndi\\:ldap* OR *jndi\\:rmi* OR *jndi\\:dns*))"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_h23-1rs-ocs" {
  case {
    condition = "a > 0"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a web application is being scanned. This identifies attacker IP addresses who are not trying to hide their attempt to attack your system. More advanced hackers will use an inconspicuous user agent. \n\n## Strategy\nInspect the user agent in the HTTP headers to determine if an IP is scanning your application and generate an `INFO` signal. \n\n## Triage and response\n1. Determine if this IP is making authenticated requests to the application.\n2. If the IP is making authenticated requests to the application:\n * Investigate the HTTP logs and determine if the user is attacking your application.\n\nThe HTTP headers in the query are from [darkqusar][1]'s [gist][2] \n\n[1]: https://gist.github.com/darkquasar\n[2]: https://gist.github.com/darkquasar/84fb2cec6cc1668795bd97c02302d380\n"
  name               = "[TBOL] Apache HTTP requests from security scanner"

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
    query           = "source:apache @http.useragent:(*burp* OR *burpcollaborator.net* OR *qualys* OR *nexpose* OR *OpenVAS* OR *Nikto* OR *Meterpreter* OR *IceWeasel* OR *DirB* OR *Comodo* OR *Tripwire* OR *Retina* OR *MBSA* OR *ImmuniWeb* OR *Netsparker* OR *Acunetix* OR *Intruder* OR *nmap* OR *CVE* OR *base64* OR *eval* OR *javascript* OR *alert*)"
  }

  type = "log_detection"
}

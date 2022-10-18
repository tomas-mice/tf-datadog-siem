resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_4no-xw9-zgj" {
  case {
    condition = "a > 0"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a web application is being scanned. This identifies attacker IP addresses who are not trying to hide their attempt to attack your system. More advanced hackers will use an inconspicuous user agent. \n\n## Strategy\nInspect the user agent in the HTTP headers to determine if an IP is scanning your application and generate an `INFO` signal. \n\n## Triage and response\n1. Determine if this IP is making authenticated requests to the application.\n2. If the IP is making authenticated requests to the application:\n * Investigate the HTTP logs and determine if the user is attacking your application.\n\nThe HTTP headers in the query are from [darkqusar][1]'s [gist][2]. \n\n[1]: https://gist.github.com/darkquasar\n[2]: https://gist.github.com/darkquasar/84fb2cec6cc1668795bd97c02302d380\n"
  name               = "[TBOL] Fastly HTTP Requests from Security Scanner"

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
    query           = "source:fastly @http.useragent:(*burp* OR *burpcollaborator.net* OR *qualys* OR *nexpose* OR *OpenVAS* OR *Nikto* OR *Meterpreter* OR *IceWeasel* OR *DirB* OR *Comodo* OR *Tripwire* OR *Retina* OR *MBSA* OR *ImmuniWeb* OR *Netsparker* OR *Acunetix* OR *Intruder* OR *nmap* OR *CVE* OR *base64* OR *eval* OR *javascript* OR *alert*)"
  }

  type = "log_detection"
}

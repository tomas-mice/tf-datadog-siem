resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_d3n-oa1-t5s" {
  case {
    condition = "high_vault_ttl > 0"
    status    = "high"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a vault token is created with an excessive time-to-live (TTL) which can be indicative of an adversary maintaining persistence. \n\n## Strategy\nMonitoring of vault audit logs where tokens are created with a time-to-live greater than 90000 seconds (25 hours). If the TTL requires modification, clone this rule and update `@auth.token_ttl:>90000` in the query. \n\n## Triage \u0026 Response\n1. Verify max TTL for tokens in the appropriate Vault configuration.\n2. If the max TTL is higher than required, modify the max TTL.\n3. Verify with the token creator to confirm that the high TTL token is legitimate.\n4. Revoke the token if it does not have a legitimate use case."
  name               = "[TBOL] Vault Token Created with Excessive TTL"

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
    name            = "high_vault_ttl"
    query           = "source:vault @request.operation:create @auth.token_ttl:>90000"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_w1w-9df-xiz" {
  case {
    condition = "root_token_created > 0 \u0026\u0026 root_token_auth_policy > 0"
    name      = "A newly created root token was used"
    status    = "high"
  }

  case {
    condition = "root_token_auth_policy > 0"
    name      = "The auth policy is root"
    status    = "high"
  }

  case {
    condition = "root_token_display_name > 0"
    name      = "The auth display name is root"
    status    = "high"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a vault root token is used. Root tokens can perform any activity and have the highest level of privileges in Vault and should only be used in emergencies. \n\n## Strategy\nThis rule lets you monitor Vault Audit Logs (`source:vault`) to detect when `root` is seen in either of these two attributes.\n\n* auth policy (`@auth.policies`)\n* auth display name (`@auth.display_name`)\n\nThis rule also lets you monitor the API endpoint `/sys/generate-root` which is used to create new root keys.\n\n## Triage \u0026 Response\n1. Determine who created the root token and when. You can get token creation time using the token accessor with `vault token lookup -accessor <accessor>`. \n2. Inspect the requests made with the root token and ensure that its usage is valid.\n3. Ensure that after the root token is no longer needed, it is revoked (`vault token revoke -accessor <token>`).\n\n## Change Log\n29 Jun 2022 - Updated queries to reduce noise levels. Replaced initial query with token creation detection."
  name               = "[TBOL] Vault Root Token Used"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@http.url_details.path"]
    name            = "root_token_created"
    query           = "source:vault @auth.policies:root @http.method:create"
  }

  query {
    aggregation     = "cardinality"
    distinct_fields = ["@http.method"]
    group_by_fields = ["@http.url_details.path"]
    name            = "root_token_auth_policy"
    query           = "source:vault @auth.policies:root"
  }

  query {
    aggregation     = "cardinality"
    distinct_fields = ["@http.method"]
    group_by_fields = ["@http.url_details.path"]
    name            = "root_token_display_name"
    query           = "source:vault @auth.display_name:root"
  }

  type = "log_detection"
}

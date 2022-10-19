resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_bkg-hll-lyu" {
  case {
    condition = "standardized_attributes > 0"
    name      = "standardized"
    status    = "info"
  }

  case {
    condition = "non_standardized_attributes > 0"
    name      = "non-standardized"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a pod is attached to the host network.\n\n## Strategy\nThis rule monitors when a create (`@http.method:create`) action occurs for a pod (`@objectRef.resource:pods`) with the host network `@requestObject.spec.hostNetwork:true` attached.\n\nAttaching the `hostNetwork` permits a pod to access the node's network adapter allowing a pod to listen to all network traffic for all pods on the node and communicate with other pods on the network namespace.\n\n## Triage and response\n1. Determine if the pod needs `hostNetwork` access.\n"
  name               = "[TBOL] Kubernetes Pod Created with hostNetwork"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@requestObject.metadata.generateName"]
    name            = "standardized_attributes"
    query           = "source:kubernetes.audit @objectRef.resource:pods @http.method:create @requestObject.spec.hostNetwork:true @http.status_code:[200 TO 299]"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@requestObject.metadata.generateName"]
    name            = "non_standardized_attributes"
    query           = "@apiVersion:audit.k8s.io* @objectRef.resource:pods @verb:create @requestObject.spec.hostNetwork:true @responseStatus.code:[200 TO 299]"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_cj6-rmd-lip" {
  case {
    condition = "standardized_attributes > 0"
    name      = "standardized"
    status    = "info"
  }

  case {
    condition = "non_standardized_attributes > 0"
    name      = "non-standardized"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a service's port is attached to the node's IP.\n\n## Strategy\nThis rule monitors when a create (`@http.method:create`) action occurs for a service (`@objectRef.resource:services`) attaching the service's port to the node's IP `@requestObject.spec.type:NodePort`.\n\nExposing the service's port to the the node's IP allows other hosts on the network namespace to access this service.\n\n## Triage and response\n1. Determine if the service needs to expose it's network connection with `NodePort` access.\n"
  name               = "[TBOL] Kubernetes Service Created with NodePort"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@objectRef.name"]
    name            = "standardized_attributes"
    query           = "source:kubernetes.audit @objectRef.resource:services @http.method:create @requestObject.spec.type:NodePort @http.status_code:[200 TO 299]"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@objectRef.name"]
    name            = "non_standardized_attributes"
    query           = "@apiVersion:audit.k8s.io* @objectRef.resource:services @verb:create @requestObject.spec.type:NodePort @responseStatus.code:[200 TO 299]"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_cjx-1c6-zka" {
  case {
    condition = "standardized_attributes > 0"
    name      = "standardized"
    status    = "info"
  }

  case {
    condition = "non_standardized_attributes > 0"
    name      = "non-standardized"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a user is creating a Kubernetes namespace.\n\n## Strategy\nThis rule monitors when a `create` action occurs for the Kubernetes namespace (`@objectRef.resource:namespaces`) to detect when a user is creating a new Kubernetes namespace.\n\n## Triage and response\n1. Determine if the user should be creating this new namespace.\n"
  name               = "[TBOL] New Kubernetes Namespace Created"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@objectRef.name", "@usr.name"]
    name            = "standardized_attributes"
    query           = "source:kubernetes.audit @objectRef.resource:namespaces @http.method:create -@objectRef.name:(\"default\" OR \"kube-system\" OR \"kube-public\") @http.status_code:[200 TO 299]"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@objectRef.name", "@user.username"]
    name            = "non_standardized_attributes"
    query           = "@apiVersion:audit.k8s.io* @objectRef.resource:namespaces @verb:create -@objectRef.name:(\"default\" OR \"kube-system\" OR \"kube-public\") @responseStatus.code:[200 TO 299]"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_ea2-xyd-alj" {
  case {
    condition = "access_denied > 10"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nIdentify when a Kubernetes user attempts to perform a high number of actions that are denied in a short amount of time.\n\n## Strategy\nThis rule identifies responses of the API server where the reason for the error is set to `Forbidden`, indicating that an authenticated user attempted to perform an action that they are not explicitly authorized to perform.\n\nThe rule flags users who receive permission denied errors on several distinct API endpoints in a short amount of time.\n\n## Triage and response\n1. Determine if the user: `{{@usr.id}}` is expected to perform the denied actions. If yes, the alert may be due to a misconfigured application or a service account with insufficient privileges.\n2. Use the Cloud SIEM `User Investigation` dashboard to review any user actions that may have occurred after the potentially malicious action."
  name               = "[TBOL] A Kubernetes user attempted to perform a high number of actions that were denied"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "7200"
  }

  query {
    aggregation     = "cardinality"
    distinct_fields = ["@http.url_details.path"]
    group_by_fields = ["@usr.id"]
    name            = "access_denied"
    query           = "source:kubernetes.audit @responseStatus.reason:Forbidden -@usr.id:(system\\:serviceaccount\\:*\\:datadog* OR system\\:kube-scheduler OR system\\:anonymous OR eks\\:authenticator OR eks\\:pod-identity-mutating-webhook OR system\\:serviceaccount\\:kube-system\\:root-ca-cert-publisher)"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_hbb-nnt-pc6" {
  case {
    condition = "standardized_attributes > 0"
    name      = "standardized"
    status    = "info"
  }

  case {
    condition = "non_standardized_attributes > 0"
    name      = "non-standardized"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a user is creating a pod in one of the Kubernetes default namespaces.\n\n## Strategy\nThis rule monitors when a create (`@http.method:create`) action occurs for a pod (`@objectRef.resource:pods`) within either of the `kube-system` or `kube-public` namespaces.\n\nThe only users creating pods in the `kube-system` namespace should be cluster administrators. Furthermore, it is best practice to not run any cluster critical infrastructure in the `kube-system` namespace.\n\nThe `kube-public` namespace is intended for Kubernetes objects which should be readable by unauthenticated users. Thus, a pod should likely not be created in the `kube-public` namespace.\n\n## Triage and response\n1. Determine if the user should be creating this new pod in one of the default namespaces.\n"
  name               = "[TBOL] Kubernetes Pod Created in Kube Namespace"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@usr.name"]
    name            = "standardized_attributes"
    query           = "source:kubernetes.audit @objectRef.resource:pods @http.method:create @objectRef.namespace:(\"kube-system\" OR \"kube-public\") @http.status_code:[200 TO 299]"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@user.username"]
    name            = "non_standardized_attributes"
    query           = "@apiVersion:audit.k8s.io* @objectRef.resource:pods @verb:create @objectRef.namespace:(\"kube-system\" OR \"kube-public\") @responseStatus.code:[200 TO 299]"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_sdo-vm7-lmc" {
  case {
    condition = "enumeration_attempt > 0"
    status    = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nIdentify when a user is attempting to enumerate their permissions.\n\n## Strategy\nThis rule identifies when a user attempts to enumerate their permissions, for example, through the use of `kubectl auth can-i --list`. This can be an indicator of an attacker having compromised a Kubernetes service account or user and attempting to determine what permissions it has.\n\n## Triage and response\n1. Determine if enumerating the permissions of the user: `{{@usr.id}}` is suspicious. For example, a service account assigned to a web application and enumerating its privileges is highly suspicious, while a group assigned to operations engineers is likely to represent legitimate activity.\n2. Use the Cloud SIEM `User Investigation` dashboard to review any user actions that may have occurred after the potentially malicious action."
  name               = "[TBOL] Kubernetes principal attempted to enumerate their permissions"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation = "count"
    name        = "enumeration_attempt"
    query       = "source:kubernetes.audit @requestObject.kind:SelfSubjectRulesReview @http.method:create -@usr.id:system\\:serviceaccount\\:*\\:datadog-kube-state-metrics"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_ufk-fvp-dti" {
  case {
    condition = "standardized_attributes > 0"
    name      = "standardized"
    status    = "info"
  }

  case {
    condition = "non_standardized_attributes > 0"
    name      = "non-standardized"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a privileged pod is created. Privileged pods remove container isolation which allows privileged actions on the host.\n\n## Strategy\nThis rule monitors when a pod (`@objectRef.resource:pods`) is created (`@http.method:create`) and the privileged security context (`@requestObject.spec.containers.securityContext.privileged`) is `true`.\n\n## Triage \u0026 Response\n1. Determine if the pod should be privileged. "
  name               = "[TBOL] New Kubernetes privileged pod created"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@objectRef.name", "@usr.name"]
    name            = "standardized_attributes"
    query           = "source:kubernetes.audit @objectRef.resource:pods @http.method:create @requestObject.spec.containers.securityContext.privileged:true"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@objectRef.name", "@user.username"]
    name            = "non_standardized_attributes"
    query           = "@apiVersion:audit.k8s.io* @objectRef.resource:pods @verb:create @requestObject.spec.containers.securityContext.privileged:true"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_wbh-pwk-fcc" {
  case {
    condition = "standardized_attributes > 0"
    name      = "standardized"
    status    = "info"
  }
  case {
    condition = "non_standardized_attributes > 0"
    name      = "non-standardized"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a user execs into a pod.\n\n## Strategy\nThis rule monitors when a user execs (`@objectRef.subresource:exec`) into to a pod (`@objectRef.resource:pods`).\n\nA user should not need to exec into a pod. Execing into a pod allows a user to execute any process in container which is not already running.\nIt is most common to execute the bash process to gain an interactive shell.\nIf this is an attacker, they can access any data which the pod has permissions to, including secrets.\n\n## Triage and response\n1. Determine if the user should be execing into a running container.\n"
  name               = "[TBOL] User Exec into a Pod"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@usr.name"]
    name            = "standardized_attributes"
    query           = "source:kubernetes.audit @objectRef.resource:pods @objectRef.subresource:exec @http.method:create @http.status_code:[101 TO 299]"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@user.username"]
    name            = "non_standardized_attributes"
    query           = "@apiVersion:audit.k8s.io* @objectRef.resource:pods @objectRef.subresource:exec @verb:create @responseStatus.code:[101 TO 299]"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_3tl-23j-fkq" {
  case {
    condition = "standardized_attributes > 0"
    name      = "standardized"
    status    = "info"
  }

  case {
    condition = "non_standardized_attributes > 0"
    name      = "non-standardized"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a user attaches to a pod.\n\n## Strategy\nThis rule monitors when a user attaches (`@objectRef.subresource:attach`) to a pod (`@objectRef.resource:pods`).\n\nA user should not need to attach to a pod. Attaching to a pod allows a user to attach to any process in a running container which may give an attacker access to sensitive data.\n\n## Triage and response\n1. Determine if the user should be attaching to a running container.\n"
  name               = "[TBOL] User Attached to a Pod"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@usr.name"]
    name            = "standardized_attributes"
    query           = "source:kubernetes.audit @objectRef.resource:pods @objectRef.subresource:attach @http.method:create @http.status_code:[101 TO 299]"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@user.username"]
    name            = "non_standardized_attributes"
    query           = "@apiVersion:audit.k8s.io* @objectRef.resource:pods @objectRef.subresource:attach @verb:create @responseStatus.code:[101 TO 299]"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_5cj-qee-ubi" {
  case {
    condition = "num_events > 0"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nIdentify when a new Kubernetes [admission controller][1] is created in the cluster.\n\nAdmission controllers can intercept all incoming requests to the API server. An attacker can use them to establish persistence or to access sensitive data (such as secrets) sent to the API server.\n\n## Strategy\nThis rule identifies when a `MutatingWebhookConfiguration` or `ValidatingWebhookConfiguration` is created.\n\n## Triage and response\n1. Determine if the admission controller being created is expected.\n2. Determine if the user: `{{@usr.id}}` should be creating the admission controller.\n3. Use the Cloud SIEM `User Investigation` dashboard to review user actions that occurred after the potentially malicious action.\n\n[1]: https://kubernetes.io/docs/reference/access-authn-authz/admission-controllers/\n"
  name               = "[TBOL] A new Kubernetes admission controller was created"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "7200"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@usr.id"]
    name            = "num_events"
    query           = "source:kubernetes.audit @http.method:create @objectRef.resource:(mutatingwebhookconfigurations OR validatingwebhookconfigurations) -@usr.id:(eks\\:cluster-bootstrap OR system\\:serviceaccount\\:kyverno\\:kyverno OR system\\:serviceaccount\\:kube-system\\:*)"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_6jw-pye-wgo" {
  case {
    condition = "num_events > 0"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\n\nIdentify when a Kubernetes user is assigned cluster-level administrative permissions.\n\n## Strategy\n\nThis rule monitory when a `ClusterRoleBinding` object is created to bind a Kubernetes user to the `cluster-admin` [default cluster-wide role](https://kubernetes.io/docs/reference/access-authn-authz/rbac/#user-facing-roles). This effectively grants the referenced user with full administrator permissions over all the Kubernetes cluster.\n\n## Triage and response\n\n1. Determine if the Kubernetes user referenced in `@requestObject.subjects` is expected to have been granted administrator permissions on the cluster\n2. Determine if the actor (`@usr.id`) is authorized to assign administrator permissions\n3. Use the Cloud SIEM `User Investigation` dashboard to review any user actions that may have occurred after the potentially malicious action. \n"
  name               = "[TBOL] A Kubernetes user was assigned cluster administrator permissions"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "7200"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@usr.id"]
    name            = "num_events"
    query           = "source:kubernetes.audit @http.method:create @requestObject.kind:ClusterRoleBinding @requestObject.roleRef.name:cluster-admin -@usr.id:system\\:apiserver"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_baj-2du-yrf" {
  case {
    condition = "standardized_attributes > 0"
    name      = "standardized"
    status    = "info"
  }

  case {
    condition = "non_standardized_attributes > 0"
    name      = "non-standardized"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a user is creating a service account in one of the Kubernetes default namespaces.\n\n## Strategy\nThis rule monitors when a create (`@http.method:create`) action occurs for a service account (`@objectRef.resource:serviceaccounts`) within either of the `kube-system` or `kube-public` namespaces.\n\nThe only users creating service accounts in the `kube-system` namespace should be cluster administrators. Furthermore, it is best practice to not run any cluster critical infrastructure in the `kube-system` namespace.\n\nThe `kube-public` namespace is intended for kubernetes objects which should be readable by unauthenticated users. Thus, a service account should likely not be created in the `kube-public` namespace.\n\n## Triage and response\n1. Determine if the user should be creating this new service account in one of the default namespaces.\n"
  name               = "[TBOL] Kubernetes Service Account Created in Kube Namespace"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@usr.name"]
    name            = "standardized_attributes"
    query           = "source:kubernetes.audit @objectRef.resource:serviceaccounts @http.method:create @objectRef.namespace:(\"kube-system\" OR \"kube-public\") @http.status_code:[200 TO 299]"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@user.username"]
    name            = "non_standardized_attributes"
    query           = "@apiVersion:audit.k8s.io* @objectRef.resource:serviceaccounts @verb:create @objectRef.namespace:(\"kube-system\" OR \"kube-public\") @responseStatus.code:[200 TO 299]"
  }

  type = "log_detection"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_9q2-247-6pt" {
  case {
    condition = "standardized_attributes > 0"
    name      = "standardized"
    status    = "info"
  }

  case {
    condition = "non_standardized_attributes > 0"
    name      = "non-standardized"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when an unauthenticated request user is permitted in Kubernetes.\n\n## Strategy\nThis rule monitors when any action is permitted (`@http.status_code:[100 TO 299]`) for an unauthenticated user (`@user.username:\\\"system:anonymous\\\"`).\nThe `/healthz` endpoint is commonly accessed unauthenticated and it is excluded in the query filter.\n\n## Triage and response\n1. Inspect all of the HTTP paths accessed and determine if any of the path should be permitted by unauthenticated users.\n2. Determine what IP addresses accessed Kubernetes endpoints which may contain sensitive data.\n"
  name               = "[TBOL] Anonymous Request Authorized"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "3600"
  }

  query {
    aggregation = "count"
    name        = "standardized_attributes"
    query       = "@apiVersion:audit.k8s.io* @usr.name:\"system:anonymous\" @http.status_code:[100 TO 299] -@http.url_details.path:\"/healthz\""
  }

  query {
    aggregation = "count"
    name        = "non_standardized_attributes"
    query       = "@apiVersion:audit.k8s.io* @user.username:\"system:anonymous\" @responseStatus.code:[100 TO 299] -@requestURI:\"/healthz\""
  }

  type = "log_detection"
}

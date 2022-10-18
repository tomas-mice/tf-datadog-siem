

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_77x-2zh-lnu" {
  case {
    condition = "compiler_in_container > 0"
    name      = "compiler_in_container"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a compiler (like `clang` or `bcc`) is executed inside of a container.\n\n## Strategy\nAfter an initial compromise, attackers may attempt to download additional tools to their victim's infrastructure. In order to make these additional tools difficult to detect or analyze, attackers sometimes deliver their tools as uncompiled code, and then compile their malicious binaries directly on the victim's infrastructure. In containerized environments, the use of compilers is especially suspicious because in production it is best practice to make containers immutable. The use of a compiler in a production container could indicate an attacker staging tools, or unwanted container configuration drift. \n\n\n## Triage \u0026 Response\n1. Determine whether or not this is expected behavior. For example, did an employee compile a tool inside of a container for an approved reason, or does an approved software compile additional files on startup?\n2. If this behavior is unexpected, attempt to contain the compromise (this may be achieved by terminating the workload, depending on the stage of attack) and look for indications of the initial compromise. Follow your organization's internal processes for investigating and remediating compromised systems.\n3. Determine the nature of the attack and the tools involved. Investigate security signals (if present) occurring around the time of the event to establish an attack path.\n4. Find and repair the root cause of the exploit.\n\n*Requires Agent version 7.27 or greater*"
  name               = "[TBOL] Compiler Executed in Container"

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
    name            = "compiler_in_container"
    query           = "@agent.rule_id:compiler_in_container"
  }

  type = "workload_security"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_7fl-lya-8di" {
  case {
    condition = "cron_at_job_creation > 0"
    name      = "cron_at_job_creation"
    status    = "high"
  }

  case {
    condition = "cron_at_job_deletion > 0"
    name      = "cron_at_job_deletion"
    status    = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect the creation or modification of new cron jobs on a system.\n\n## Strategy\nCron is a task scheduling system that runs tasks on a time-based schedule. Attackers can use cron jobs to gain persistence on a system, or even to run malicious code at system-boot. Cron jobs can also be used for remote code execution, or to run a process under a different user-context.\n\n## Triage and response\n1. Check to see which cron task was created or modified.\n2. Check whether the cron task was created or modified by a known user or process.\n3. If these changes are not acceptable, roll back the host or container in question to an acceptable configuration.\n\n\n*Requires Agent version 7.27 or greater*"
  name               = "[TBOL] Cron AT Job Creation"

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
    name            = "cron_at_job_creation"
    query           = "@agent.rule_id:(cron_at_job_creation OR cron_at_job_creation_chmod OR cron_at_job_creation_chown OR cron_at_job_creation_link OR cron_at_job_creation_rename OR cron_at_job_creation_open OR cron_at_job_creation_utimes) -(@file.name:*.dpkg-new AND @process.executable.name:dpkg)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["host"]
    name            = "cron_at_job_deletion"
    query           = "@agent.rule_id:cron_at_job_creation_unlink"
  }

  type = "workload_security"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_7x4-tpj-rur" {
  case {
    condition = "cryptominer_args > 0"
    name      = "cryptominer_args"
    status    = "high"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\n\nDetect when a process launches with arguments associated with cryptocurrency miners.\n\n## Strategy\n\nCryptocurrency miners are often executed with unique arguments such as `--donate-level`. This can be used to identify suspicious processes with high confidence.\n\n## Triage and response\n\n1. Isolate the workload.\n2. Use host metrics to verify if cryptocurrency mining is taking place. This will be indicated by an increase in CPU usage.\n3. Review the process tree and related signals to determine the initial entry point.\n\n*Requires agent version 7.27 or greater*"
  name               = "[TBOL] Process arguments match a cryptocurrency miner"

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
    name            = "cryptominer_args"
    query           = "@agent.rule_id:cryptominer_args"
  }

  type = "workload_security"
}


resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_8ri-hbf-uvd" {
  case {
    condition = "pwnkit_privilege_escalation > 0"
    name      = "pwnkit_privilege_escalation"
    status    = "critical"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\n\nDetect exploitation of CVE-2021-4034 dubbed PwnKit.\n\n## Strategy\n\nPwnKit is a local privilege escalation vulnerability originally found by [Qualys](https://blog.qualys.com/vulnerabilities-threat-research/2022/01/25/pwnkit-local-privilege-escalation-vulnerability-discovered-in-polkits-pkexec-cve-2021-4034). It affects PolicyKit’s `pkexec` program, which is a SUID-root program installed by default on many Linux distributions. This detection triggers whenever `pkexec` is executed by a non-root process with the `SHELL` and `PATH` variables set.\n\n## Triage and response\n\n1. Determine the purpose of the process executing `pkexec`.\n2. Look for any suspicious actions or commands being executed after the `pkexec` execution.\n3. If this behavior is unexpected, it could indicate a malicious actor has access to the host and is attempting to increase privileges for post exploitation actions. Investigate application logs or APM data to look for indications of the initial compromise. Follow your organization's internal processes for investigating and remediating compromised systems.\n4. Ensure to update the PolicyKit package to its latest version to mitigate the vulnerability. If updating is not feasible, remove the SUID bit that is set by default on `pkexec` with the following command: `sudo chmod -s \\$(which pkexec)`.\n\n*Requires Agent version 7.27 or greater*"
  name               = "[TBOL] Pwnkit privilege escalation attempt"

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
    name            = "pwnkit_privilege_escalation"
    query           = "@agent.rule_id:pwnkit_privilege_escalation"
  }

  type = "workload_security"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_8zt-xtl-i4r" {
  case {
    condition = "python_cli_code_suspicious > 0"
    name      = "python_cli_code_suspicious"
    status    = "high"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\n\nDetect Python code being provided and executed on the command line using the `-c` flag.\n\n## Strategy\n\nPython code can be specified on the command line using the `-c` flag. Attackers may use this to run \"one-liners\" which establish communication with an attacker-run server, download additional malware, or otherwise advance their mission. Libraries such as `socket` and `subprocess` are commonly used in these attacks and are unlikely to have a legitimate purpose when used in this way.\n\n## Triage and response\n\n1. Review the process tree and identify if the Python command is expected.\n2. If the command is not expected, contain the host or container and roll back to a known good configuration.\n3. Start the incident response process and determine the initial entry point.\n\n*Requires Agent version 7.27 or greater*"
  name               = "[TBOL] Python executed with suspicious arguments"

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
    name            = "python_cli_code_suspicious"
    query           = "@agent.rule_id:python_cli_code @process.args:(*SOCK_STREAM* OR *subprocess* OR *\\/bash* OR *\\/bin\\/sh*  OR *pty.spawn*)"
  }

  type = "workload_security"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_9jv-211-rl2" {
  case {
    condition = "credential_modified_non_bin > 0"
    name      = "credential_modified_non_bin"
    status    = "high"
  }

  case {
    condition = "credential_modified_standard > 0"
    name      = "credential_modified_standard"
    status    = "info"
  }

  case {
    condition = "credential_modified > 0"
    name      = "credential_modified"
    status    = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect modifications to sensitive credential files from non-standard processes.\n\n## Strategy\nEspecially in production, all credentials should be either defined as code, or static. Drift and unmonitored changes to these credentials can open up attack vectors for adversaries, and cause your organization to be out of compliance with any frameworks or regulations that you are subject to. This detection watches for the modification of sensitive credential files which should not be changed outside of their definitions as code (or static definitions). The Linux commands `vipw` and `vigr` are the standard way to modify shadow and gshadow files respectively. Other processes interacting with these sensitive credential files is highly suspicious and should be investigated.\n\n## Triage and response\n1. Identify the user or process that changed the credential file(s).\n2. Identify what was changed in the credential files.\n3. If these changes are not acceptable, roll back contain the host or container in question to an acceptable configuration.\n\n*Requires Agent version 7.27 or greater*"
  name               = "[TBOL] Either /etc/shadow/ or /etc/gshadow was modified by a non-standard tool"

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
    name            = "credential_modified"
    query           = "@agent.rule_id:(credential_modified OR credential_modified_chmod OR credential_modified_chown OR credential_modified_link OR credential_modified_rename OR credential_modified_open OR credential_modified_unlink OR credential_modified_utimes) -(@process.executable.name:containerd @process.args:info) -@process.executable.name:dockerd"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["host"]
    name            = "credential_modified_standard"
    query           = "@agent.rule_id:(credential_modified OR credential_modified_chmod OR credential_modified_chown OR credential_modified_link OR credential_modified_rename OR credential_modified_open OR credential_modified_unlink OR credential_modified_utimes) -(@process.executable.name:containerd @process.args:info) -@process.executable.name:dockerd @process.comm:(adduser OR useradd OR groupadd OR userdel OR deluser OR chage)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["host"]
    name            = "credential_modified_non_bin"
    query           = "@agent.rule_id:(credential_modified OR credential_modified_chmod OR credential_modified_chown OR credential_modified_link OR credential_modified_rename OR credential_modified_open OR credential_modified_unlink OR credential_modified_utimes) -(@process.executable.name:containerd @process.args:info) -@process.executable.name:dockerd -@process.executable.path:(\\/usr\\/sbin\\/* OR \\/usr\\/bin\\/* OR \\/bin\\/*)"
  }

  type = "workload_security"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_9p8-elv-hds" {
  case {
    condition = "ptrace_antidebug > 0"
    name      = "ptrace_antidebug"
    status    = "high"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect usage of the ptrace system call with the `PTRACE_TRACEME` argument, indicating a program actively attempting to avoid debuggers attaching to the process. This behavior is typically indicative of malware activity.\n\n## Strategy\nThe ptrace system call provides a means for one process to observe and control the execution of another process. This system call allows a process to modify the execution of another process, including changing memory and register values. One limitation of this system call is that a process can only have one trace, and malicious actors have been observed making use of this limitation to prevent debuggers from attaching to malicious processes for the purpose of forensics or analysis.\n\n## Triage and response\n1. Check the name of the process using TRACEME\n2. If this file is not known or authorized, contain the host or container and roll back to a known good configuration. Initiate the incident response process.\n*Requires Agent version 7.35 or greater*"
  name               = "[TBOL] A ptrace syscall was used with the PTRACE_TRACEME request to prevent a debugger from attaching to the process"

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
    name            = "ptrace_antidebug"
    query           = "@agent.rule_id:ptrace_antidebug"
  }

  type = "workload_security"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_ahl-qjb-pfq" {
  case {
    condition = "suspicious_container_client > 0"
    name      = "suspicious_container_client"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect execution of a container management utility (e.g., `kubectl`) in a container.\n\n## Strategy\nAfter an attacker's initial intrusion into a victim container (for example, through a web shell exploit), they may attempt to escalate privileges, break out of the container, or exfiltrate secrets by running container management/orchestration utilities. This detection triggers when execution of one of a set of common container management utilities (like `kubectl` or `kubelet`) is detected in a container. If this is unexpected behavior, it could indicate an attacker attempting to compromise your containers and host.\n\n## Triage and response\n1. Determine whether or not this is expected behavior.\n2. If this behavior is unexpected, attempt to contain the compromise (this may be achieved by terminating the workload, depending on the stage of attack) and look for indications of initial compromise. Follow your organization's internal processes for investigating and remediating compromised systems.\n3. Determine the nature of the attack and utilities involved. Investigate security signals (if present) occurring around the time of the event to establish an attack path.\n4. Find and repair the root cause of the exploit.\n\n*Requires version 7.27 or higher*"
  name               = "[TBOL] Container management utility in container"

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
    name            = "suspicious_container_client"
    query           = "@agent.rule_id:suspicious_container_client"
  }

  type = "workload_security"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_al4-5ta-ojo" {
  case {
    condition = "package_management_in_container > 0"
    name      = "package_management_in_container"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect installation of software using a package management utility (`apt` or `yum`) in a container.\n\n## Strategy\nAfter an attacker's initial intrusion into a victim's container (for example, through a web shell exploit), they may attempt to install tools and utilities for a variety of malicious purposes. This detection triggers when one of a set of common package management utilities installs a package in a container. Package management in containers is against best practices which highly emphasize immutability. If this is unexpected behavior, it could indicate an attacker attempting to install tools to further compromise your systems.\n\n\n## Triage and response\n1. Determine whether or not this is expected behavior.\n2. If this behavior is unexpected, attempt to contain the compromise. This may be achieved by terminating the workload, depending on the stage of attack.\n3. Look for indications of initial compromise. Follow your organization's internal processes for investigating and remediating compromised systems.\n4. Determine the nature of the attack and the tools involved. Investigate security signals (if present) occurring around the time of the event to establish an attack path.\n5. Find and repair the root cause of the exploit.\n\n*Requires Agent version 7.27 or greater*"
  name               = "[TBOL] Package installation in container"

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
    name            = "package_management_in_container"
    query           = "@agent.rule_id:package_management_in_container @process.args:(add OR *install OR \"-i\")"
  }

  type = "workload_security"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_by8-kr9-42b" {
  case {
    condition = "kernel_module_load_from_memory > 0"
    name      = "kernel_module_load_from_memory"
    status    = "high"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nKernel modules can be used to automatically execute code when a host starts up. Attackers sometimes use kernel modules to gain persistence on a particular host, ensuring that their code is executed even after a system reboot. Kernel modules can also help attackers gain elevated permissions on a system.\n\nLoading a malicious kernel module is a type of rootkit. Rootkits often create backdoor access and hide evidence of themselves. This includes process, file, and network activity.\n\n## Strategy\nKernel modules are loaded from the `/lib/modules` directory in Linux by default. In an attempt to thwart forensics, attackers sometimes attempt to load malicious kernel modules from memory so as not to leave artifacts on disk. This detection watches for all new kernel modules being loaded directly from memory. \n\n## Triage and response\n1. Check the name of the new kernel module created.\n2. If the new kernel module is not expected, contain the host or container and roll back to a known good configuration. Initiate the incident response process.\n\n*Requires Agent version 7.35 or greater*"
  name               = "[TBOL] A new kernel module was loaded from memory"

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
    name            = "kernel_module_load_from_memory"
    query           = "@agent.rule_id:kernel_module_load_from_memory"
  }

  type = "workload_security"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_cde-1mc-8yp" {
  case {
    condition = "ssh_authorized_keys_chmod > 0 || ssh_authorized_keys_chown > 0 || ssh_authorized_keys_link > 0 || ssh_authorized_keys_rename > 0 || ssh_authorized_keys_open > 0 || ssh_authorized_keys_unlink > 0 || ssh_authorized_keys_utimes > 0"
    name      = "ssh_authorized_keys"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect modifications to authorized SSH keys.\n\n## Strategy\nSSH is a commonly used key-based authentication mechanism. In this system, the authorized_keys file specifies SSH keys that can be used to authenticate as a specific user on the system. Attacker's may modify the authorized_keys file to authorize attacker-owned SSH keys. This allows the attacker to maintain persistence on a system as a specific user.\n\n## Triage and response\n1. Check what changes were made to authorized_keys, and under which user.\n2. Determine whether any keys were added. If so, determine if the added keys belong to known trusted users.\n3. If they keys in question are not acceptable, roll back the host or container in question to a known trusted SSH configuration.\n\n\n*Requires Agent version 7.27 or greater*"
  name               = "[TBOL] SSH Authorized Keys Modified"

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
    name            = "ssh_authorized_keys_chmod"
    query           = "@agent.rule_id:(ssh_authorized_keys OR ssh_authorized_keys_chmod)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["host"]
    name            = "ssh_authorized_keys_chown"
    query           = "@agent.rule_id:(ssh_authorized_keys OR ssh_authorized_keys_chown)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["host"]
    name            = "ssh_authorized_keys_link"
    query           = "@agent.rule_id:(ssh_authorized_keys OR ssh_authorized_keys_link)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["host"]
    name            = "ssh_authorized_keys_rename"
    query           = "@agent.rule_id:(ssh_authorized_keys OR ssh_authorized_keys_rename)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["host"]
    name            = "ssh_authorized_keys_open"
    query           = "@agent.rule_id:(ssh_authorized_keys OR ssh_authorized_keys_open)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["host"]
    name            = "ssh_authorized_keys_unlink"
    query           = "@agent.rule_id:(ssh_authorized_keys OR ssh_authorized_keys_unlink)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["host"]
    name            = "ssh_authorized_keys_utimes"
    query           = "@agent.rule_id:(ssh_authorized_keys OR ssh_authorized_keys_utimes)"
  }

  type = "workload_security"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_csu-xmy-5ox" {
  case {
    condition = "potential_cryptominer > 0"
    name      = "potential_cryptominer"
    status    = "high"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\n\nAttackers often use compromised cloud infrastructure to mine cryptocurrency. \n\n## Strategy\n\nDetect when a process performs a DNS lookup for a domain related to cryptomining.\n\n## Triage and response\n\n`{{@process.executable.name}}` performed a DNS lookup for `{{@dns.question.name}}`\n\n1. Contain the host or container and roll back to a known good configuration.\n2. Review the process tree and determine the initial entry point.\n\n*Requires Agent version 7.36 or greater*"
  name               = "[TBOL] DNS Lookup Made for Cryptocurrency Mining Pool"

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
    name            = "potential_cryptominer"
    query           = "@agent.rule_id:potential_cryptominer"
  }

  type = "workload_security"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_dmb-rzl-xeh" {
  case {
    condition = "user_created_tty > 0"
    name      = "user_created_tty"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect the creation of a new user on the system using an interactive session.\n\n## Strategy\nAttacker's may add local accounts to systems that they have compromised to maintain access to those systems. If an attacker has gained a sufficient level of access (like admin privileges) on a system, they can make a new user for themselves.\nIn production systems, users should be created in the base image of the system (for example, the AMI or other VM image), or they should be created programmatically by configuration management tools. The creation of a new user by an interactive (human) session is suspicious.\n\n## Triage \u0026 Response\n1. Determine whether the creation of a new user is expected behavior.\n2. If this behavior is unexpected, attempt to contain the compromise (possibly by terminating the workload, depending on the stage of attack), and look for indications of the initial compromise. Follow your organization's internal processes for investigating and remediating compromised systems.\n3. Determine the scope of the attack. Investigate whether or not multiple systems had this user added around the same time, and whether the systems impacted follow a pattern. For example, if a user was added to multiple systems, do they share the same workload or base image? What other activity occurred directly before or after the user was added?\n\n\n*Requires Agent version 7.27 or greater*"
  name               = "[TBOL] User Created Interactively"

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
    name            = "user_created_tty"
    query           = "@agent.rule_id:user_created_tty"
  }

  type = "workload_security"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_ebd-yje-mmc" {
  case {
    condition = "interactive_shell_in_container > 0"
    name      = "interactive_shell_in_container"
    status    = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect the execution of a shell with the interactive flag (`-i`) in a container.\n\n## Strategy\nAfter an attacker's initial intrusion into a victim container (for example, through a web shell exploit), they may attempt to escalate privileges, break out of the container, or exfiltrate secrets by running interative shell utilities inside of the container. This detection triggers when execution of one of a set of common Linux shell utilities (like `bash` or `sh`) is detected in a container with the interactive flag (`-i`). If this is unexpected behavior, it could indicate an attacker attempting to run arbitrary commands inside of your containers and potentially break out onto the host.\n\n## Triage \u0026 Response\n1. Inspect the command line arguments of the shell process execution to determine if the shell was run with the `-i` flag.\n2. If this behavior is unexpected, attempt to contain the compromise (possibly by terminating the workload, depending on the stage of attack) and look for indications of the initial compromise. Follow your organization's internal processes for investigating and remediating compromised systems.\n3. Determine the nature of the attack and utilities involved. Investigate security signals (if present) occurring around the time of the event to establish an attack path.\n4. Find and repair the root cause of the exploit.\n"
  name               = "[TBOL] Interactive Shell in Container"

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
    name            = "interactive_shell_in_container"
    query           = "@agent.rule_id:interactive_shell_in_container -@process.comm:(hostname OR sed OR find)"
  }

  type = "workload_security"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_etn-ryv-y5z" {
  case {
    condition = "confluence_server_spawned_shell_potential_rce > 0"
    name      = "confluence_server_spawned_shell_potential_rce"
    status    = "high"
  }

  case {
    condition = "java_shell_execution_unusual > 0"
    name      = "java_shell_execution_unusual"
    status    = "high"
  }

  case {
    condition = "java_shell_execution_suspicious > 0"
    name      = "java_shell_execution_suspicious"
    status    = "medium"
  }

  case {
    condition = "java_shell_execution > 0"
    name      = "java_shell_execution"
    status    = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect common shell utilities, HTTP utilities, or shells spawned by a Java process.\n\n## Strategy\nMany applications (like some databases, web servers, and search engines) run as Java processes. Attackers may take advantage of flaws in programs built with these applications (for example, SQL injection on a database running as a Java process). This detection triggers when a Java process spawns common shell utilities, HTTP utilities, or shells. If this is unexpected behavior, it could indicate an attacker attempting to compromise your host.\n\n## Triage and response\n1. Determine the nature and purpose of the Java process.\n2. Determine whether there is an approved purpose for the Java process to execute shells and utilities.\n3. If this behavior is unexpected, attempt to contain the compromise (this may be achieved by terminating the workload, depending on the stage of attack). Investigate application logs or APM data to look for indications of the initial compromise. Follow your organization's internal processes for investigating and remediating compromised systems.\n4. Find and repair the root cause of the exploit.\n\n*Requires Agent version 7.27 or greater*"
  name               = "[TBOL] Java process spawned shell/utility"

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
    name            = "java_shell_execution"
    query           = "@agent.rule_id:java_shell_execution"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["host"]
    name            = "java_shell_execution_suspicious"
    query           = "@agent.rule_id:java_shell_execution @process.executable.name:(uname OR cat OR ls)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["host"]
    name            = "java_shell_execution_unusual"
    query           = "@agent.rule_id:java_shell_execution @process.executable.name:(curl OR wget OR whoami)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["host"]
    name            = "confluence_server_spawned_shell_potential_rce"
    query           = "@agent.rule_id:java_shell_execution @process.envs:CONFLUENCE*"
  }

  type = "workload_security"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_gnr-dzj-qay" {
  case {
    condition = "database_shell_execution > 0"
    name      = "database_shell_execution"
    status    = "critical"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect common shell utilities, HTTP utilities, or shells spawned by a database process (e.g., MySQL, PostgreSQL, MongoDB).\n\n## Strategy\nAttacks on databases often take advantage of oversights in I/O sanitization and validation to run attacker statements and commands. For example, these attacks could take the form of database query injection, which can signal the beginning of an intrusion and wider attack, by establishing a web shell or exfiltrating data. This detection triggers when common shell utilities, HTTP utilities, or shells are spawned by one of a set of database processes (e.g., MySQL, MongoDB, PostgreSQL). This is atypical behavior for a database. If this is unexpected behavior, it could indicate an attacker attempting to compromise your database or host machine.\n\n## Triage and response\n1. Determine whether or not there is an approved purpose for your database to execute shells and utilities.\n2. If this behavior is unexpected, attempt to contain the compromise (this may be achieved by terminating the workload, depending on the stage of attack). Investigate application logs or APM data to look for indications of the initial compromise. Follow your organization's internal processes for investigating and remediating compromised systems.\n3. Find and repair the root cause of the exploit.\n\n*Requires Agent version 7.27 or greater*"
  name               = "[TBOL] Database spawned shell/utility"

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
    name            = "database_shell_execution"
    query           = "@agent.rule_id:database_shell_execution -@process.ancestors.executable.name:initdb -@process.args:\"locale -a\""
  }

  type = "workload_security"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_gqi-tvp-gho" {
  case {
    condition = "nsswitch_conf_mod_chmod > 0 || nsswitch_conf_mod_chown > 0 || nsswitch_conf_mod_link > 0 || nsswitch_conf_mod_rename > 0 || nsswitch_conf_mod_open > 0 || nsswitch_conf_mod_unlink > 0 || nsswitch_conf_mod_utimes > 0"
    name      = "nsswitch_conf_mod"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect modifications to nsswitch.conf.\n\n## Strategy\nThe Name Service Switch (nsswitch) configuration file is used to point system services and other applications to the sources of name-service information. This name-service information includes where the password file is stored, publickey information, and more. An attacker may attempt to modify nsswitch.conf in order to inject attacker-owned information into the authentication process. For instance, the attacker could point to a malicious password file and then login to privileged user accounts.\n\n## Triage and response\n1. Check to see what changes were made to nsswitch.conf.\n2. Check if critical name-service sources were changed, and whether the changes were a part of known system-setup or maintenance.\n3. If these changes are unauthorized, roll back the host in question to a known good nsswitch.conf, or replace the system with a known-good system image.\n\n*Requires Agent version 7.27 or greater*"
  name               = "[TBOL] Nsswitch Configuration Modified"

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
    name            = "nsswitch_conf_mod_chmod"
    query           = "@agent.rule_id:(nsswitch_conf_mod OR nsswitch_conf_mod_chmod)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["host"]
    name            = "nsswitch_conf_mod_chown"
    query           = "@agent.rule_id:(nsswitch_conf_mod OR nsswitch_conf_mod_chown)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["host"]
    name            = "nsswitch_conf_mod_link"
    query           = "@agent.rule_id:(nsswitch_conf_mod OR nsswitch_conf_mod_link)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["host"]
    name            = "nsswitch_conf_mod_rename"
    query           = "@agent.rule_id:(nsswitch_conf_mod OR nsswitch_conf_mod_rename)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["host"]
    name            = "nsswitch_conf_mod_open"
    query           = "@agent.rule_id:(nsswitch_conf_mod OR nsswitch_conf_mod_open)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["host"]
    name            = "nsswitch_conf_mod_unlink"
    query           = "@agent.rule_id:(nsswitch_conf_mod OR nsswitch_conf_mod_unlink)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["host"]
    name            = "nsswitch_conf_mod_utimes"
    query           = "@agent.rule_id:(nsswitch_conf_mod OR nsswitch_conf_mod_utimes)"
  }

  type = "workload_security"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_gzs-1ai-hqk" {
  case {
    condition = "paste_site > 0"
    name      = "paste_site"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\n\nPaste sites such as pastebin.com can be used by attackers to host malicious scripts, configuration files, and other text data. The files are then downloaded to the host using a network utility such as `wget` or `curl`. These sites may also be used to exfiltrate data.\n\n## Strategy\n\nDetect when a process performs a DNS lookup for a paste site.\n\n## Triage and response\n1. Check if the application `{{@process.executable.name}}` is expected to make connections to `{{@dns.question.name}}`.\n2. If the DNS lookup is unexpected, contain the host or container and roll back to a known good configuration.\n3. Follow your organization's internal processes for investigating and remediating compromised systems.\n\n\n*Requires Agent version 7.36 or greater*"
  name               = "[TBOL] DNS Lookup Made for Paste Site"

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
    name            = "paste_site"
    query           = "@agent.rule_id:paste_site"
  }

  type = "workload_security"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_hn1-cnw-y9j" {
  case {
    condition = "ptrace_injection > 0"
    name      = "ptrace_injection"
    status    = "high"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect usage of the ptrace systemcall to inject code into another process.\n\n## Strategy\nThe ptrace system call provides a means for one process to observe and control the execution of another process. This system call allows a process to modify the execution of another process, including changing memory and register values. Malicious actors have been observed using ptrace to inject code into another process, for the purposes of defense evasion and privilege escalation.\n\n## Triage and response\n1. Check the name of the process doing the injection (the tracer).\n2. Identify if the file doing the injection (the tracer) is authorized.\n3. If the tracer is not authorized in this environment, or is not normally known to use the ptrace syscall, contain the host or container and roll back to a known good configuration. Initiate the incident response process.\n\n*Requires Agent version 7.35 or greater*"
  name               = "[TBOL] A ptrace syscall was used to inject into another process"

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
    name            = "ptrace_injection"
    query           = "@agent.rule_id:ptrace_injection"
  }

  type = "workload_security"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_i7v-hsk-mzb" {
  case {
    condition = "shell_history_tamper > 0"
    name      = "shell_history_tamper"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect the tampering of shell command history on a host or container. \n\n## Strategy\nCommands used within a terminal are contained within a local file so users can review applications, scripts, or processes that were previously executed.  Adversaries tamper with the integrity of the shell command history by deletion, truncation, or the linking of `/dev/null` by use of a symlink. This allows adversaries to obfuscate their actions and delay the incident response process. \n\n## Triage and response\n1. Review the tampering action taken against the shell command history files.\n2. Review the user or process that performed the action against the shell command history.\n3. Determine whether or not this is expected behavior.\n4. If this activity is not expected, contain the host or container, and roll back to a known good configuration.\n\n*Requires Agent version 7.27 or greater*\n"
  name               = "[TBOL] An attempt was made to tamper with shell command history"

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
    name            = "shell_history_tamper"
    query           = "@agent.rule_id:(shell_history_symlink OR shell_history_truncated OR shell_history_deleted)"
  }

  type = "workload_security"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_ier-pwd-9gk" {
  case {
    condition = "passwd_execution > 0"
    name      = "passwd_execution"
    status    = "high"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect execution of the `passwd` or `chpasswd` commands.\n\n## Strategy\nThe `passwd` operating system command is used to change user account passwords. The `chpasswd` does this in bulk. If this is unexpected behavior, it could indicate an attacker attempting to compromise your host machine and achieve persistence. This detection is triggered when execution of the `passwd` or `chpasswd` command is detected.\n\n## Triage and response\n1. Determine which user executed the command and whether or not this is allowed or expected behavior.\n2. If this behavior is unexpected, attempt to contain the compromise (this may be achieved by terminating the workload, depending on the stage of attack) and look for indications of initial compromise. Follow your organization's internal processes for investigating and remediating compromised systems.\n3. Investigate security signals (if present) occurring around the time of the event to establish an attack path.\n4. Find and repair the root cause of the exploit.\n\n*Requires Agent version 7.27 or greater*\n"
  name               = "[TBOL] Passwd utility executed"

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
    name            = "passwd_execution"
    query           = "@agent.rule_id:passwd_execution"
  }

  type = "workload_security"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_kdd-laq-lxp" {
  case {
    condition = "apparmor_modified_tty > 0"
    name      = "apparmor_modified_tty"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect modification of AppArmor profiles using an interactive session.\n\n## Strategy\nAfter an initial intrusion, attackers may attempt to disable security tools to avoid possible detection of their offensive tools and activities. [AppArmor][1] is a Linux Security Module (LSM) feature that confines programs to a limited set of resources. Disabling AppArmor could help an attacker run disallowed tools and gain access to resources that are otherwise blocked. This detection looks for commands that disable or modify AppArmor during interactive sessions, which is highly irregular in production environments.\n\n## Triage \u0026 Response\n1. Determine whether or not this is expected behavior.\n2. If this behavior is unexpected, attempt to contain the compromise (possibly by terminating the workload, depending on the stage of attack) and look for indications of the initial compromise. Follow your organization's internal processes for investigating and remediating compromised systems.\n3. Determine the nature of the attack and utilities involved. Investigate security signals (if present) occurring around the time of the event to establish an attack path.\n4. Find and repair the root cause of the exploit.\n\n*Requires Agent version 7.27 or greater*\n\n[1]: https://wiki.ubuntu.com/AppArmor\n"
  name               = "[TBOL] AppArmor Profile Modified"

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
    name            = "apparmor_modified_tty"
    query           = "@agent.rule_id:apparmor_modified_tty"
  }

  type = "workload_security"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_mgr-51c-0bs" {
  case {
    name   = "new_binary_execution_in_container"
    status = "high"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a file that is not part of the original container image has been created and executed within the container.\n\n## Strategy\nAttackers sometimes add scripts to running containers to exploit some functionality or automate some actions. Normally, containers are meant to be immutable environments, and when you require new scripts or other executable files, you add them to the container image itself and not to the running container. This detection identifies when newly created files are executed shortly after file creation or modification.\n\nThis rule uses the New Value detection method. Datadog will learn the historical behavior of a specified field in agent logs and then create a signal when unfamiliar values appear.\n\n## Triage \u0026 Response\n1. Determine whether the file executing is expected to be present in the container. \n2. If this behavior is unexpected, attempt to contain the compromise (possibly by terminating the workload, depending on the stage of attack), and look for indications of the initial compromise. Follow your organization's internal processes for investigating and remediating compromised systems.\n3. Determine the scope of the attack. Investigate whether the file was added to multiple containers around the same time, and whether the affected systems follow a pattern. For example, if a file was seen executing in multiple containers, do the containers share the same workload or base image? What other activity occurred directly before or after the user was added?\n\n\n*Requires Agent version 7.29 or greater*"
  name               = "[TBOL] A file was recently created and executed inside of a container"

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
    group_by_fields = ["container.id"]
    metric          = "@process.comm"
    metrics         = ["@process.comm"]
    name            = "new_binary_execution_in_container"
    query           = "@agent.rule_id:new_binary_execution_in_container"
  }

  type = "workload_security"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_nr0-ki6-yyg" {
  case {
    condition = "ssl_certificate_tampering > 0"
    name      = "ssl_certificate_tampering"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect potential tampering with SSL certificates.\n\n## Strategy\nSSL certificates, and other forms of trust controls establish trust between systems. Attackers may attempt to subvert trust controls such as SSL certificates in order to trick systems or users into trusting attacker-owned assets such as fake websites, or falsely signed applications.\n\n## Triage and response\n1. Check whether there were any planned changed to the SSL certificates stores in your infrastructure.\n2. If these changes are not acceptable, roll back the host or container in question to a known trustworthy configuration.\n3. Investigate security signals (if present) occurring around the time of the event to establish an attack path.\n4. Find and repair the root cause of the exploit.\n\n*Requires Agent version 7.27 or greater*\n"
  name               = "[TBOL] SSL Certificate Tampering"

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
    name            = "ssl_certificate_tampering"
    query           = "@agent.rule_id:(ssl_certificate_tampering OR ssl_certificate_tampering_chmod OR ssl_certificate_tampering_chown OR ssl_certificate_tampering_link OR ssl_certificate_tampering_rename OR ssl_certificate_tampering_open OR ssl_certificate_tampering_unlink OR ssl_certificate_tampering_utimes) -@process.executable.path:\\/usr\\/sbin\\/update-ca-certificates -@process.parent.executable.path:\\/usr\\/sbin\\/update-ca-certificates"
  }

  type = "workload_security"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_nt6-8ey-adn" {
  case {
    condition = "runc_modification > 0"
    name      = "runc_modification"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect modifications to the `runc` binary outside of the normal package management lifecycle.\n\n## Strategy\n[CVE-2019-5736][1], a vulnerability in `runc` through version 1.0-rc6 could allow attackers to overwrite the host `runc` binary, which allows the attacker to effectively escape a running container, and gain root access on the underlying host.\nAny modifications to `runc` (outside of standard package management upgrades) could be exploiting this vulnerability to gain root access to the system.\n\n## Triage \u0026 Response\n1. Check to see which user or process changed the `runc` binary.\n2. If these changes are not acceptable, roll back contain the host in question to an acceptable configuration.\n3. Update `runc` to a version above 1.0-rc6 (or Docker 18.09.2 and above).\n4. Determine the nature of the attack and utilities involved. Investigate security signals (if present) occurring around the time of the event to establish an attack path.\n\n*Requires Agent version 7.27 or greater*\n\n[1]: https://nvd.nist.gov/vuln/detail/CVE-2019-5736\n"
  name               = "[TBOL] Runc Binary Modified"

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
    name            = "runc_modification"
    query           = "@agent.rule_id:runc_modification"
  }

  type = "workload_security"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_nu6-lch-hk1" {
  case {
    condition = "dirty_pipe_attempt > 0"
    name      = "dirty_pipe_attempt"
    status    = "high"
  }

  case {
    condition = "dirty_pipe_exploitation > 0"
    name      = "dirty_pipe_exploitation"
    status    = "critical"
  }

  case {
    condition = "dirty_pipe_root > 0"
    name      = "dirty_pipe_root"
    status    = "critical"
  }

  case {
    condition = "dirty_pipe_bin > 0"
    name      = "dirty_pipe_bin"
    status    = "critical"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\n\nDetect exploitation of CVE-2022-0847 \"Dirty Pipe\". Dirty Pipe is a vulnerability in the Linux kernel which allows underprivileged processes to write to arbitrary readable files, leading to privilege escalation. \n\n## Strategy\n\nThis detection triggers when the `splice()` syscall is made and the `PIPE_BUF_FLAG_CAN_MERGE` flag is set. Explanation of the vulnerability and exploitation can be found in the [public disclosure](https://dirtypipe.cm4all.com/).\n\n## Triage \u0026 Response\n\n1. Determine if the host is vulnerable. This vulnerability affects kernel versions starting from 5.8. After its discovery, it was fixed for all currently maintained releases of Linux in versions 5.16.11, 5.15.25, and 5.10.102. The exploit was successful if the field `splice.pipe_exit_flag` is `PIPE_BUF_FLAG_CAN_MERGE`.\n2. Attempt to contain the compromise (possibly by terminating the workload, depending on the stage of attack) and look for indications of the initial compromise. Follow your organization's internal processes for investigating and remediating compromised systems.\n3. If the host is vulnerable, update the kernel to a patched version.\n\n*Requires Agent version 7.35 or greater*"
  name               = "[TBOL] Dirty Pipe Exploitation"

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
    name            = "dirty_pipe_attempt"
    query           = "@agent.rule_id:dirty_pipe_attempt"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["host"]
    name            = "dirty_pipe_exploitation"
    query           = "@agent.rule_id:dirty_pipe_exploitation -@process.executable.path:(\"/usr/bin/grep\" OR \"/bin/grep\")"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["host"]
    name            = "dirty_pipe_root"
    query           = "@agent.rule_id:dirty_pipe_exploitation (@file.uid:0 OR @file.gid:0) -@process.executable.path:(\"/usr/bin/grep\" OR \"/bin/grep\")"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["host"]
    name            = "dirty_pipe_bin"
    query           = "@agent.rule_id:dirty_pipe_exploitation @file.path:(*\\/bin\\/* OR *\\/boot\\/*) -@process.executable.path:(\"/usr/bin/grep\" OR \"/bin/grep\")"
  }

  type = "workload_security"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_oej-alh-3fv" {
  case {
    condition = "net_util_in_container > 0"
    name      = "net_util_in_container"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect execution of a network utility executed from a suspicious location in a container.\n\n## Strategy\nAfter an attacker's initial intrusion into a victim container (for example, through a web shell exploit), they may attempt to use network utilities for a variety of malicious purposes (for example, reconnaissance or data exfiltration). This detection triggers when execution of one of a set of network utilities (for example, `nslookup`, `netcat`) is detected in a container. Different utilities may serve different purposes in an attack; for example, DNS tools like `nslookup` could be involved in a DNS data exfiltration attack, and `netcat` could indicate a backdoor and data exfiltration. If this is unexpected behavior, it could indicate an attacker attempting to compromise your containers and host.\n\nThese utilities executed by a file located in `/tmp` or another writeable directory could indicate a malicious script attempting to perform actions on the host. These actions may include downloading additional tools or exfiltrating data.\n\n## Triage and response\n1. Determine whether or not this is expected behavior.\n2. Review the ancestors for unexpected processes or files executed.\n3. If this behavior is unexpected, attempt to contain the compromise (this may be achieved by terminating the workload, depending on the stage of attack) and look for indications of the initial compromise. Follow your organization's internal processes for investigating and remediating compromised systems.\n4. Determine the nature of the attack and network tools involved. Investigate security signals (if present) occurring around the time of the event to establish an attack path and signals from other tools. For example, if a DNS exfiltration attack is suspected, examine DNS traffic and servers if available.\n5. Find and repair the root cause of the exploit.\n\n*Requires Agent version 7.34 or greater*"
  name               = "[TBOL] Network utility executed in container"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "threshold"
    evaluation_window                 = "300"
    keep_alive                        = "3600"
    max_signal_duration               = "86400"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["@container.id", "host"]
    name            = "net_util_in_container"
    query           = "@agent.rule_id:net_util_in_container @process.ancestors.executable.path:(*\\/tmp\\/* OR \\/home\\/* OR \\/run\\/user\\/*)"
  }

  type = "workload_security"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_ox4-v3h-5cm" {
  case {
    condition = "systemd_modification_chmod > 0 || systemd_modification_chown > 0 || systemd_modification_link > 0 || systemd_modification_rename > 0 || systemd_modification_open > 0 || systemd_modification_unlink > 0 || systemd_modification_utimes > 0"
    name      = "systemd_modification"
    status    = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect modifications to system services.\n\n## Strategy\nEspecially in production, systems should be generated based on standard images such as AMIs for Amazon EC2, VM images in Azure, or GCP images. Systemd is the default service manager in many Linux distributions. It manages the lifecycle of background processes and services, and can be used by an attacker to establish persistence in the system. Attackers can do this by injecting code into existing systemd services, or by creating new ones. Systemd services can be started on system boot, and therefore attacker code can persist through system reboots.\n\n## Triage and response\n1. Check to see what service was modified of created.\n2. Identify whether it is a known service, being modified by a known user and/or process.\n3. If these changes are not acceptable, roll back the host in question to an acceptable configuration.\n\n*Requires Agent version 7.27 or greater*"
  name               = "[TBOL] Systemd Modification"

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
    name            = "systemd_modification_chmod"
    query           = "@agent.rule_id:(systemd_modification OR systemd_modification_chmod) -(@process.executable.name:containerd @process.args:info) -@process.executable.name:dockerd"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["host"]
    name            = "systemd_modification_chown"
    query           = "@agent.rule_id:(systemd_modification OR systemd_modification_chown) -(@process.executable.name:containerd @process.args:info) -@process.executable.name:dockerd"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["host"]
    name            = "systemd_modification_link"
    query           = "@agent.rule_id:(systemd_modification OR systemd_modification_link) -(@process.executable.name:containerd @process.args:info) -@process.executable.name:dockerd"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["host"]
    name            = "systemd_modification_rename"
    query           = "@agent.rule_id:(systemd_modification OR systemd_modification_rename) -(@process.executable.name:containerd @process.args:info) -@process.executable.name:dockerd"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["host"]
    name            = "systemd_modification_open"
    query           = "@agent.rule_id:(systemd_modification OR systemd_modification_open) -(@process.executable.name:containerd @process.args:info) -@process.executable.name:dockerd"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["host"]
    name            = "systemd_modification_unlink"
    query           = "@agent.rule_id:(systemd_modification OR systemd_modification_unlink) -(@process.executable.name:containerd @process.args:info) -@process.executable.name:dockerd"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["host"]
    name            = "systemd_modification_utimes"
    query           = "@agent.rule_id:(systemd_modification OR systemd_modification_utimes) -(@process.executable.name:containerd @process.args:info) -@process.executable.name:dockerd"
  }

  type = "workload_security"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_p1h-kcz-fwn" {
  case {
    name   = "k8s_pod_service_account_token_accessed"
    status = "high"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "Detects when the Kubernetes pod service account token has been viewed by a user.\n\n## Strategy\nKubernetes uses service accounts as its own internal identity system. Pods can authenticate with the Kubernetes API server using an auto-mounted token that only the Kubernetes API server could validate. These service account tokens can be used to authenticate to the Kubernetes API.\nKubernetes uses service accounts as its own internal identity system. Pods can authenticate with the Kubernetes API server using an auto-mounted token that only the Kubernetes API server could validate. These service account tokens can be used to authenticate to the Kubernetes API.\n\nThis rule uses the New Value detection method. Datadog will learn the historical behavior of a specified field in agent logs and then create a signal when unfamiliar values appear.\n\n## Triage and response\n1. Determine which user executed the command to read the token and determine if that access is authorized.\n2. If this behavior is unexpected, attempt to contain the compromise (this may be achieved by terminating the workload, depending on the stage of attack), and look for indications of initial compromise. Follow your organization's internal processes for investigating and remediating compromised systems.\n4. Determine the nature of the attack and network tools involved. Investigate security signals (if present) occurring around the time of the event to establish an attack path and signals from other tools. For example, if a DNS exfiltration attack is suspected, examine DNS traffic and servers if available.\n5. Find and repair the root cause of the exploit.\n\n*Requires Agent version 7.27 or greater*"
  name               = "[TBOL] Kubernetes Pod Service Account Token Accessed by unusual process"

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
    group_by_fields = ["container.id"]
    metric          = "@process.comm"
    metrics         = ["@process.comm"]
    name            = "k8s_pod_service_account_token_accessed"
    query           = "@agent.rule_id:k8s_pod_service_account_token_accessed"
  }

  type = "workload_security"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_qdu-vb5-wwc" {
  case {
    condition = "selinux_disable_enforcement > 0"
    name      = "selinux_disable_enforcement"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when SELinux enforcement is disabled.\n\n## Strategy\nThis detection monitors the change of SELinux enforcing mode.\n\n## Triage \u0026 Response\n1. Check which user or process disabled SELinux enforcing mode.\n2. If the change is not expected, roll back to enable SELinux enforcing mode.\n3. Investigate security signals (if present) occurring around the time of the event to establish an attack path.\n4. Find and repair the root cause of the attack.\n\n*Requires Agent version 7.30 or greater*"
  name               = "[TBOL] SELinux enforcement status was disabled"

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
    name            = "selinux_disable_enforcement"
    query           = "@agent.rule_id:selinux_disable_enforcement"
  }

  type = "workload_security"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_rnx-llt-lml" {
  case {
    name   = "potential_web_shell"
    status = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect shell utilities, HTTP utilities, or shells spawned by a web server.\n\n## Strategy\nWeb shell attacks often involve attackers loading and running malicious files onto a victim machine, creating a backdoor on the compromised system. Attackers use web shells for a variety of purposes, and they can signal the beginning of an intrusion or wider attack. This detection triggers when shell utilities, HTTP utilities, or shells are spawned by a common web server process.\n\nThis rule uses the New Value detection method. Datadog will learn the historical behavior of a specified field in agent logs and then create a signal when unfamiliar values appear.\n\n## Triage and response\n1. Determine whether or not there is an approved purpose for your web application to execute shells and utilities.\n2. If this behavior is unexpected, attempt to contain the compromise (this may be achieved by terminating the workload, depending on the stage of attack). Investigate application logs or APM data to look for indications of the initial compromise. Follow your organization's internal processes for investigating and remediating compromised systems.\n3. Find and repair the root cause of the exploit.\n\n*Requires Agent version 7.27 or greater*"
  name               = "[TBOL] Webapp process spawned unusual shell/utility"

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
    group_by_fields = ["host"]
    metric          = "@process.comm"
    metrics         = ["@process.comm"]
    name            = "potential_web_shell"
    query           = "@agent.rule_id:potential_web_shell"
  }

  type = "workload_security"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_rqo-jg3-3oe" {
  case {
    condition = "kernel_module > 0"
    name      = "kernel_module"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nKernel modules can be used to automatically execute code when a host starts up. Attackers sometimes use kernel modules to gain persistence on a particular host, ensuring that their code is executed even after a system reboot. Kernel modules can also help attackers gain elevated permissions on a system.\n\nLoading a malicious kernel module is a type of rootkit. Rootkits often create backdoor access and hide evidence of themselves. This includes process, file, and network activity.\n\n## Strategy\nKernel modules are loaded from the `/lib/modules` directory in Linux. This detection watches for all new files created under that directory.\n\n## Triage and response\n1. Check the name of the new kernel module created.\n2. Check which user or process created the module.\n3. If the new kernel module is not expected, contain the host or container and roll back to a known good configuration. Initiate the incident response process.\n\n*Requires Agent version 7.27 or greater*"
  name               = "[TBOL] A kernel module was added to /lib/modules/"

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
    name            = "kernel_module"
    query           = "@agent.rule_id:(kernel_module OR kernel_module_chmod OR kernel_module_chown OR kernel_module_link OR kernel_module_rename OR kernel_module_open OR kernel_module_unlink OR kernel_module_utimes) -@process.envs:DPKG_FRONTEND_LOCKED"
  }

  type = "workload_security"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_rtz-lys-zvq" {
  case {
    condition = "common_net_intrusion_util > 0"
    name      = "common_net_intrusion_util"
    status    = "high"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect execution of the `nmap` network utility.\n\n## Strategy\n`nmap` is a network utility commonly used by attackers to understand a victim's network topology and vulnerabilities. After an attacker's initial intrusion into a host (for example, through a web shell exploit, container breakout), they may attempt to use `nmap` to do reconnaissance. This detection triggers when an execution of `nmap` is detected on a system. If this is unexpected behavior, it could indicate an attacker attempting to compromise your systems.\n\n## Triage and response\n1. Determine which user executed `nmap` and whether this is allowed or expected behavior.\n2. If this behavior is unexpected, attempt to contain the compromise (this may be achieved by terminating the workload, depending on the stage of attack) and look for indications of initial compromise. Follow your organization's internal processes for investigating and remediating compromised systems.\n3. Determine the nature of the attack and network tools involved. Investigate the security signals (if present) occurring around the time of the event to establish an attack path.\n4. Find and repair the root cause of the exploit.\n\n\n*Requires Agent version 7.27 or greater*"
  name               = "[TBOL] Nmap Execution Detected"

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
    name            = "common_net_intrusion_util"
    query           = "@agent.rule_id:common_net_intrusion_util"
  }

  type = "workload_security"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_sl6-4jt-hbr" {
  case {
    condition = "pci_11_5_critical_binaries_chmod > 0 || pci_11_5_critical_binaries_chown > 0 || pci_11_5_critical_binaries_link > 0 || pci_11_5_critical_binaries_rename > 0 || pci_11_5_critical_binaries_open > 0 || pci_11_5_critical_binaries_open > 0 || pci_11_5_critical_binaries_unlink > 0 || pci_11_5_critical_binaries_utimes > 0"
    name      = "pci_11_5_critical_binaries"
    status    = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect modifications of critical system binaries.\n\n## Strategy\nPCI-DSS is the payment-card industry's compliance framework. Any systems that handle credit card data and transactions from the major credit card companies must be PCI-DSS compliance. Control 11.5 of the PCI-DSS framework states that organizations must \"alert personnel to unauthorized modifications (including changes, additions, and deletions) of critical system files, configuration files, or content files\". On Linux, critical system binaries are typically stored in `/bin/`, `/sbin/`, or `/usr/sbin/`. This rule tracks any modifications to those directories.\n\n## Triage and response\n1. Identify which user or process changed the critical system binaries.\n2. If these changes were not authorized, and you cannot confirm the safety of the changes, roll back the host or container in question to an acceptable configuration.\n\n*Requires Agent version 7.27 or greater*"
  name               = "[TBOL] Critical System Binaries"

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
    name            = "pci_11_5_critical_binaries_chmod"
    query           = "@agent.rule_id:(pci_11_5_critical_binaries OR pci_11_5_critical_binaries_chmod) -@process.executable.name:(pip OR pip3 OR npm OR dockerd) -(@process.executable.name:containerd @process.args:info)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["host"]
    name            = "pci_11_5_critical_binaries_chown"
    query           = "@agent.rule_id:(pci_11_5_critical_binaries OR pci_11_5_critical_binaries_chown) -@process.executable.name:(pip OR pip3 OR npm OR dockerd) -(@process.executable.name:containerd @process.args:info)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["host"]
    name            = "pci_11_5_critical_binaries_link"
    query           = "@agent.rule_id:(pci_11_5_critical_binaries OR pci_11_5_critical_binaries_link) -@process.executable.name:(pip OR pip3 OR npm OR dockerd) -(@process.executable.name:containerd @process.args:info)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["host"]
    name            = "pci_11_5_critical_binaries_rename"
    query           = "@agent.rule_id:(pci_11_5_critical_binaries OR pci_11_5_critical_binaries_rename) -@process.executable.name:(pip OR pip3 OR npm OR dockerd) -(@process.executable.name:containerd @process.args:info)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["host"]
    name            = "pci_11_5_critical_binaries_open"
    query           = "@agent.rule_id:(pci_11_5_critical_binaries OR pci_11_5_critical_binaries_open) -@process.executable.name:(pip OR pip3 OR npm OR dockerd) -(@process.executable.name:containerd @process.args:info)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["host"]
    name            = "pci_11_5_critical_binaries_unlink"
    query           = "@agent.rule_id:(pci_11_5_critical_binaries OR pci_11_5_critical_binaries_unlink) -@process.executable.name:(pip OR pip3 OR npm OR dockerd) -(@process.executable.name:containerd @process.args:info)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["host"]
    name            = "pci_11_5_critical_binaries_utimes"
    query           = "@agent.rule_id:(pci_11_5_critical_binaries OR pci_11_5_critical_binaries_utimes) -@process.executable.name:(pip OR pip3 OR npm OR dockerd) -(@process.executable.name:containerd @process.args:info)"
  }

  type = "workload_security"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_sse-sdl-dhi" {
  case {
    condition = "ip_check_domain > 0"
    name      = "ip_check_domain"
    status    = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\n\nIP check services return the public IP of the client. They are used legitimately for configuration purposes when utilizing infrastructure as code. They can be abused by attackers to determine the organization they have compromised.\n\n## Strategy\n\nDetect when a DNS lookup is done for a domain belonging to an IP check service.\n\n## Triage and response\n\n1. Determine if `{{@process.executable.name}}` is expected to make a connection to `{{@dns.question.name}}`.\n2. If the DNS lookup is unexpected, contain the host or container and roll back to a known good configuration.\n3. Start incident response and determine the initial entry point.\n\n*Requires Agent version 7.36 or greater*"
  name               = "[TBOL] DNS Lookup Made for IP Check Service"

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
    name            = "ip_check_domain"
    query           = "@agent.rule_id:ip_check_domain"
  }

  type = "workload_security"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_suo-ykp-s7r" {
  case {
    condition = "pam_modification_chmod > 0 || pam_modification_chown > 0 || pam_modification_link > 0 || pam_modification_rename > 0 || pam_modification_open > 0 || pam_modification_unlink > 0 || pam_modification_utimes > 0"
    name      = "pam_modification"
    status    = "info"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect modifications to `pam.d` directory.\n\n## Strategy\nLinux Pluggable Authentication Modules (PAM) provide authentication for applications and services. Authentication modules in the PAM system are setup and configured under the `/etc/pam.d/` directory. An attacker may attempt to modify or add an authentication module in PAM in order to bypass the authentication process, or reveal system credentials.\n\n## Triage and response\n1. Identify if the changes to the path `{{@file.path}}` were part of known system setup or mainenance.\n2. If these changes were unauthorized, roll back the host in question to a known good PAM configuration, or replace the system with a known-good system image.\n\n*Required agent version 7.27 or higher*\n"
  name               = "[TBOL] PAM Configuration Files Modification"

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
    name            = "pam_modification_chmod"
    query           = "@agent.rule_id:(pam_modification OR pam_modification_chmod)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["host"]
    name            = "pam_modification_chown"
    query           = "@agent.rule_id:(pam_modification OR pam_modification_chown)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["host"]
    name            = "pam_modification_link"
    query           = "@agent.rule_id:(pam_modification OR pam_modification_link)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["host"]
    name            = "pam_modification_rename"
    query           = "@agent.rule_id:(pam_modification OR pam_modification_rename)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["host"]
    name            = "pam_modification_open"
    query           = "@agent.rule_id:(pam_modification OR pam_modification_open)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["host"]
    name            = "pam_modification_unlink"
    query           = "@agent.rule_id:(pam_modification OR pam_modification_unlink)"
  }

  query {
    aggregation     = "count"
    group_by_fields = ["host"]
    name            = "pam_modification_utimes"
    query           = "@agent.rule_id:(pam_modification OR pam_modification_utimes)"
  }

  type = "workload_security"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_sxx-b3j-vbu" {
  case {
    condition = "aws_metadata_service > 0"
    name      = "aws_metadata_service"
    status    = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect when a network utility (like `cURL` or `Wget`) is used to access the cloud instance metadata service (IMDS) in an interactive session.\n\n## Strategy\nThe cloud instance metadata service is a link-local HTTP endpoint that provides data about a given cloud instance. One function is to provide temporary security credentials so that they do not need to be stored on the host. Because IMDS can be used to fetch security credentials, attackers may use it to escalate privileges in order to access other cloud resources. This detection identifies when Linux network utilities are used in an interactive session to access the metadata service. Especially in production environments, it is unusual for this activity to occur interactively.\n\n## Triage \u0026 Response\n1. Determine whether or not this is expected behavior. For example, did an employee run commands for an approved reason, or does a configuration management utility use an interactive session?\n2. If this behavior is unexpected, attempt to contain the compromise (possibly by terminating the workload, depending on the stage of attack) and look for indications of the initial compromise. Follow your organization's internal processes for investigating and remediating compromised systems.\n3. Determine the nature of the attack and the tools involved. Investigate security signals (if present) occurring around the time of the event to establish an attack path.\n4. Using cloud audit logs, identify if the attached identity was misused.\n5. Find and repair the root cause of the exploit.\n\n*Requires Agent version 7.27 or greater*"
  name               = "[TBOL] EC2 Instance Metadata Service Accessed via Network Utility"

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
    name            = "aws_metadata_service"
    query           = "@agent.rule_id:aws_metadata_service @process.tty:*"
  }

  type = "workload_security"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_uah-3b6-pu1" {
  case {
    name   = "aws_eks_service_account_token_accessed"
    status = "high"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetects when the AWS EKS service account token has been viewed by a user.\n\n## Strategy\nAWS provides an authentication mechanism called [IAM Roles for Service Accounts](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html) to allow Kubernetes workloads such as pods to securely authenticate to AWS without hardcoding credentials.\n\nThe authentication token made available by AWS is located at `/var/run/secrets/eks.amazonaws.com/serviceaccount/token` and can be exchanged for AWS credentials using `sts:AssumeRoleWithWebIdentity`. It is consequently an attractive target for attackers.\n\nThis rule uses the New Value detection method. Datadog will learn the historical behavior of a specified field in agent logs and then create a signal when unfamiliar values appear.\n\n## Triage and response\n1. Determine which user executed the command to read the token and determine if that access is authorized.\n2. If this behavior is unexpected, attempt to contain the compromise (this may be achieved by terminating the workload, depending on the stage of attack), and look for indications of initial compromise. Follow your organization's internal processes for investigating and remediating compromised systems.\n4. Determine the nature of the attack and network tools involved. Investigate security signals (if present) occurring around the time of the event to establish an attack path and signals from other tools. For example, if a DNS exfiltration attack is suspected, examine DNS traffic and servers if available.\n5. Find and repair the root cause of the exploit.\n\n*Requires Agent version 7.27 or greater*"
  name               = "[TBOL] AWS EKS Service Account Token Accessed by unusual process"

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
    group_by_fields = ["container.id"]
    metric          = "@process.comm"
    metrics         = ["@process.comm"]
    name            = "aws_eks_service_account_token_accessed"
    query           = "@agent.rule_id:aws_eks_service_account_token_accessed"
  }

  type = "workload_security"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_vrk-0po-khu" {
  case {
    condition = "net_util > 0"
    name      = "net_util"
    status    = "low"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nDetect execution of a network utility executed from a suspicious location on a host.\n\n## Strategy\nAfter an attacker's initial intrusion into a host (for example, through a web shell exploit, or a container breakout), they may attempt to use network utilities for a variety of malicious purposes (for example, reconnaissance, or data exfiltration). This detection triggers when execution of one of a set of network utilities (for example, `nslookup`, `netcat`) is detected on a host. Different utilities may serve different purposes in an attack; for example, DNS tools like `nslookup` could be involved in a DNS data exfiltration attack, and `netcat` could indicate a backdoor and data exfiltration. If this is unexpected behavior, it could indicate an attacker attempting to compromise your host.\n\nThese utilities executed by a file located in `/tmp` or another writeable directory could indicate a malicious script attempting to perform actions on the host. These actions may include downloading additional tools or exfiltrating data.\n\n## Triage and response\n1. Determine which user executed the utility and whether or not this is allowed or expected behavior.\n2. Review the ancestors for unexpected processes or files executed. \n3. If this behavior is unexpected, attempt to contain the compromise (this may be achieved by terminating the workload, depending on the stage of attack), and look for indications of initial compromise. Follow your organization's internal processes for investigating and remediating compromised systems.\n4. Determine the nature of the attack and network tools involved. Investigate security signals (if present) occurring around the time of the event to establish an attack path and signals from other tools. For example, if a DNS exfiltration attack is suspected, examine DNS traffic and servers if available.\n5. Find and repair the root cause of the exploit.\n\n*Requires Agent version 7.34 or greater*"
  name               = "[TBOL] Network utility executed"

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
    name            = "net_util"
    query           = "@agent.rule_id:net_util @process.ancestors.executable.path:(*\\/tmp\\/* OR *\\/home\\/*)"
  }

  type = "workload_security"
}

resource "datadog_security_monitoring_rule" "tfer--security_monitoring_rule_yr9-dkv-xb0" {
  case {
    name   = "new_kernel_module"
    status = "medium"
  }

  enabled            = "false"
  has_extended_title = "true"
  message            = "## Goal\nAttackers can leverage malicious kernel modules to gain persistence on a system, ensuring their malicious code is executed even after a system reboot. Kernel modules can also help attackers gain elevated permissions and cover their tracks through the use of a rootkit.\n\nLoading a malicious kernel module can be a type of rootkit. Rootkits often create backdoor access and hide evidence of themselves. This includes process, file, and network activity.\n\n## Strategy\nKernel modules are loaded from the `/lib/modules` directory in Linux by default, however attackers may attempt to load kernel modules from other locations as well. This detection detects all kernel module loads. \n\nThis rule uses the New Value detection method. Datadog will learn the historical behavior of a specified field in agent logs and then create a signal when unfamiliar values appear.\n\n## Triage and response\n1. Check the name of the new kernel module created.\n2. Check the name of the process loading the kernel module.\n3. If the new kernel module is not expected, contain the host or container and roll back to a known good configuration. Initiate the incident response process."
  name               = "[TBOL] An unrecognized kernel module was loaded"

  options {
    decrease_criticality_based_on_env = "false"
    detection_method                  = "new_value"
    evaluation_window                 = "0"
    keep_alive                        = "3600"
    max_signal_duration               = "86400"

    new_value_options {
      forget_after       = "14"
      learning_duration  = "1"
      learning_method    = "duration"
      learning_threshold = "0"
    }
  }

  query {
    aggregation     = "new_value"
    group_by_fields = ["host"]
    metric          = "@module.name"
    metrics         = ["@module.name"]
    name            = "new_kernel_module"
    query           = "@agent.rule_id:(kernel_module_load OR new_kernel_module_audit OR kernel_module_load_container OR new_kernel_module_audit_container)"
  }

  type = "workload_security"
}

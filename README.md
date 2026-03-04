#  Splunk Log Analysis Project -- SSH Brute Force & Privilege Escalation Detection

##  Project Overview

This project simulates a real-world attack scenario in a cloud
environment and demonstrates how to detect attacker activity using
Splunk log analysis.

The environment was built in AWS EC2 where:

-   A Splunk server was deployed for centralized log monitoring
-   A victim Ubuntu machine was configured to forward authentication
    logs
-   An SSH brute-force attack was performed using Hydra
-   Privilege escalation and post-exploitation techniques were executed
-   Custom dashboards were created to visualize and detect attacker
    behavior

------------------------------------------------------------------------

#  Environment Architecture

## 🔹 Infrastructure Components

-   **SIEM Platform:** Splunk Enterprise
-   **Log Forwarding:** Splunk Universal Forwarder
-   **Cloud Provider:** Amazon Web Services (AWS EC2)
-   **Attack Tool:** Hydra (Kali Linux)
-   **Operating System:** Ubuntu 24.04 LTS

------------------------------------------------------------------------

#  Phase 0 -- Environment Setup

## 1️⃣ Splunk Server Setup

-   Created Ubuntu 24.04 EC2 instance
-   Installed Splunk Enterprise
-   Changed hostname for visibility
-   Configured receiving port for log ingestion
-   Created index: `victim-machine-logs`

📷 Image:

    images/splunk-machine-setup.png

------------------------------------------------------------------------

## 2️⃣ Victim Machine Setup

-   Created Ubuntu 24.04 EC2 instance
-   Changed hostname for visibility
-   Enabled time synchronization
-   Created user `testuser`
-   Installed Splunk Universal Forwarder
-   Forwarded `/var/log/auth.log` to Splunk server
-   Enabled SSH authentication

📷 Image:

    images/victim-machine-setup.png

------------------------------------------------------------------------

#  PHASE 1 --- Initial Access (SSH Brute Force)

## Attack Execution

-   Executed Hydra against SSH service
-   Multiple failed login attempts generated
-   Successful login achieved as `testuser`

📷 Image:

    images/hydra-bruteforce.png

## Logs Generated (Ubuntu 24.04 -- /var/log/auth.log)

-   Failed password for testuser 
-   Accepted password for testuser 
-   Session opened for user testuser

------------------------------------------------------------------------

##  Detection Query -- Failed vs Accepted Logins

``` spl
index="victim-machine-logs" earliest="03/04/2026:02:48:00" latest="03/04/2026:02:59:00"
sourcetype="auth" (Event="Failed password" OR Event="Accepted password")
| stats count by src_ip User Event
| fillnull value=0
| sort - count
```

📷 Dashboard Image:

    images/failed-vs-accepted-chart.png

------------------------------------------------------------------------

#  PHASE 2 --- Privilege Escalation

## Commands Executed

    sudo -l
    sudo su -

## Logs Generated

-   sudo: testuser : TTY=...
-   session opened for user root
-   session closed for user root

## Detection Query

``` spl
index="victim-machine-logs"
"COMMAND=/usr/bin/su -"
| eval command=mvindex(split(_raw,"COMMAND="),1)
| table _time host command
```



------------------------------------------------------------------------

#  PHASE 3 --- Persistence (Backdoor Account Creation)

## Commands Executed

    sudo adduser backupadmin
    sudo usermod -aG sudo backupadmin

## Detection Query -- Account Creation

``` spl
index="victim-machine-logs"
"COMMAND=/usr/sbin/adduser"
| eval executed_by=mvindex(split(_raw,"sudo: "),1)
| eval executed_by=mvindex(split(executed_by," :"),0)
| eval command=mvindex(split(_raw,"COMMAND="),1)
| eval new_user=mvindex(split(command," "),1)
| table _time host executed_by new_user command
```


------------------------------------------------------------------------

#  PHASE 4 --- Sensitive File Access

## Commands Executed

    sudo nano /etc/passwd
    cat /etc/passwd
    cat /etc/shadow
    ls /root

## Detection Query

``` spl
index="victim-machine-logs"
"/etc/passwd"
| eval executed_by=mvindex(split(_raw,"sudo: "),1)
| eval executed_by=mvindex(split(executed_by," :"),0)
| eval command=mvindex(split(_raw,"COMMAND="),1)
| table _time host executed_by command
```


------------------------------------------------------------------------

#  PHASE 5 --- Tool Installation

## Command Executed

    sudo apt install netcat

## Detection Query

``` spl
index="victim-machine-logs"
"apt install"
| eval executed_by=mvindex(split(_raw,"sudo: "),1)
| eval executed_by=mvindex(split(executed_by," :"),0)
| eval command=mvindex(split(_raw,"COMMAND="),1)
| table _time host executed_by command
```


------------------------------------------------------------------------

#  PHASE 6 --- Enumeration

## Commands Executed

    whoami
    id

These commands simulate attacker reconnaissance after gaining access.



------------------------------------------------------------------------

#  Clean Attack Timeline Query

``` spl
index="victim-machine-logs"
("su -" OR "adduser" OR "usermod -aG sudo" OR "/etc/passwd" OR "apt install")
| eval executed_by=mvindex(split(_raw,"sudo: "),1)
| eval executed_by=mvindex(split(executed_by," :"),0)
| eval command=mvindex(split(_raw,"COMMAND="),1)
| eval action_type=case(
    searchmatch("su -"), "Privilege Escalation",
    searchmatch("adduser"), "Persistence - Account Creation",
    searchmatch("usermod -aG sudo"), "Privilege Grant",
    searchmatch("/etc/passwd"), "Credential Access",
    searchmatch("apt install"), "Tool Installation"
)
| table _time host executed_by action_type command
| sort _time
```

📷 Image:

    images/attack-timeline-dashboard.png

------------------------------------------------------------------------


#  Key Security Learnings

-   Brute force attacks create identifiable spikes in failed
    authentication logs
-   Successful login after multiple failures is high-risk behavior
-   Privilege escalation using `sudo su -` is high-value detection
-   Unauthorized account creation is strong persistence indicator
-   Accessing `/etc/shadow` is critical severity
-   Installing post-exploitation tools indicates attacker staging

------------------------------------------------------------------------

#  Conclusion

This project demonstrates end-to-end:

-   Attack simulation
-   Log ingestion & parsing
-   Detection engineering
-   Dashboard visualization
-   Incident timeline reconstruction

It replicates real SOC investigation workflows using Splunk in a
controlled AWS lab environment.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

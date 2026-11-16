# Security Log Monitoring and Threat Detection Using Splunk

## Project Overview

This project focuses on monitoring, analyzing, and investigating Windows Security Event Logs using **Splunk Enterprise**, a Security Information and Event Management (SIEM) platform.

The project simulates basic Security Operations Center (SOC) activities by analyzing authentication events, identifying repeated failed login attempts, monitoring user account activities, and detecting potentially suspicious behavior.

Splunk Search Processing Language (SPL) was used to create security monitoring queries, analyze event patterns, and generate insights from collected security logs.

## Objectives

- Collect and analyze Windows Security Event Logs.
- Monitor successful and failed login attempts.
- Identify repeated authentication failures.
- Detect potential brute-force activity.
- Monitor user account creation and privileged account activity.
- Identify security audit log clearing events.
- Develop security monitoring queries and dashboards.
- Document investigation findings and security recommendations.

## Tools and Technologies

| Tool | Purpose |
|---|---|
| Splunk Enterprise | SIEM and log monitoring |
| Splunk Universal Forwarder | Windows log collection and forwarding |
| Windows Event Viewer | Viewing Windows security events |
| Windows 10/11 | Log source |
| SPL | Searching and analyzing security events |

## Windows Security Event IDs Analyzed

| Event ID | Description | Security Purpose |
|---|---|---|
| 4624 | Successful login | Authentication monitoring |
| 4625 | Failed login | Detecting suspicious login attempts |
| 4634 | User logged out | Session monitoring |
| 4648 | Explicit credential usage | Monitoring credential usage |
| 4672 | Special privileges assigned | Privileged activity monitoring |
| 4720 | User account created | Account creation monitoring |
| 1102 | Security audit log cleared | Detecting possible log tampering |

## Project Implementation

### 1. Splunk Installation and Configuration

- Installed and configured Splunk Enterprise.
- Set up log collection from Windows Security Event Logs.
- Configured Splunk Universal Forwarder for continuous log forwarding.
- Verified that security events were searchable in Splunk.

### 2. Security Event Monitoring

Analyzed Windows authentication and security events using Splunk.

Monitored:
- Successful login attempts.
- Failed login attempts.
- Repeated authentication failures.
- New user account creation.
- Privileged account activity.
- Security audit log clearing.

### 3. SPL Query Development

Developed 15 Splunk SPL searches to analyze security events and identify suspicious activity patterns.

Some of the detection use cases included:

**Failed Login Monitoring**
```spl
index=main EventCode=4625
| table _time Account_Name EventCode IpAddress
| sort -_time
```

**Repeated Failed Login Detection**
```spl
index=main EventCode=4625
| stats count by Account_Name
| sort -count
```

**Potential Brute-Force Detection**
```spl
index=main EventCode=4625
| bin _time span=10m
| stats count by _time Account_Name IpAddress
| where count >= 5
| sort -count
```

**New User Account Monitoring**
```spl
index=main EventCode=4720
| table _time Account_Name EventCode
```

### 4. Security Monitoring Dashboard

Designed a security monitoring dashboard to provide visibility into Windows authentication and security events.

Dashboard components:
- Failed login attempts.
- Successful login attempts.
- Login activity trends.
- Accounts with repeated authentication failures.
- Security event distribution.

### 5. Security Investigation

Investigated authentication-related events and potentially suspicious activities using Splunk search queries.

The investigation focused on:
- Identifying repeated failed login attempts.
- Reviewing successful authentication events.
- Analyzing accounts associated with multiple login failures.
- Monitoring new account creation.
- Identifying security audit log clearing events.

## Investigation Findings

The project demonstrated how Splunk can be used to:

- Identify failed authentication events through Windows Event ID 4625.
- Monitor successful authentication through Event ID 4624.
- Highlight accounts with repeated login failures.
- Identify potential brute-force patterns.
- Monitor account creation and privileged activity.
- Detect security audit log clearing events.

These findings demonstrate the importance of centralized log monitoring in identifying suspicious activities that require further investigation.

*Note: Actual event counts, account names, IP addresses, and confirmed security incidents should be documented using results from the collected lab data.*

## Security Recommendations

1. Implement strong password policies.
2. Monitor repeated failed authentication attempts.
3. Investigate unusual login patterns and source IP addresses.
4. Review newly created user accounts.
5. Monitor privileged account activities.
6. Protect security logs against unauthorized modification.
7. Configure alerts for suspicious authentication patterns.
8. Perform regular security log reviews.

## Skills Demonstrated

- Security Information and Event Management (SIEM)
- Splunk Enterprise
- Splunk Search Processing Language (SPL)
- Windows Event Log Analysis
- Security Log Monitoring
- Authentication Monitoring
- Brute-Force Detection
- Threat Detection
- Security Event Investigation
- Dashboard Creation
- Security Alert Configuration
- Incident Documentation

## Conclusion

This project provided practical exposure to SIEM operations and security log analysis using Splunk Enterprise.

By collecting and analyzing Windows Security Event Logs, developing SPL queries, and investigating authentication-related activities, the project demonstrated how security monitoring tools help identify potential threats and improve security visibility.

It strengthened practical knowledge of log analysis, authentication monitoring, threat detection, and security investigation processes relevant to entry-level SOC Analyst and Cybersecurity roles.

## Disclaimer

This project was developed for educational and cybersecurity learning purposes in a controlled lab environment. Detection results are indicators for investigation and should not be considered confirmation of malicious activity without further validation.

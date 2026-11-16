# Security Investigation Report
## Security Log Monitoring and Threat Detection Using Splunk

### 1. Project Overview

**Project Name:** Security Log Monitoring and Threat Detection Using Splunk  
**Tool Used:** Splunk Enterprise  
**Log Source:** Windows Security Event Logs  
**Category:** SIEM (Security Information and Event Management)

### 2. Objective

The objective of this investigation was to monitor and analyze Windows security events using Splunk Enterprise to identify suspicious authentication activities, repeated failed login attempts, and potentially unauthorized account access.

The investigation demonstrates how SIEM tools can help security analysts monitor system activity, detect unusual behavior, and investigate potential security threats.

### 3. Investigation Scope

The following Windows Security Event IDs were selected for analysis:

| Event ID | Description |
|---|---|
| 4624 | Successful login |
| 4625 | Failed login |
| 4634 | User logged out |
| 4648 | Login using explicit credentials |
| 4672 | Special privileges assigned |
| 4720 | User account created |
| 1102 | Security audit log cleared |

### 4. Investigation Methodology

The investigation was conducted using the following steps:

1. Installed and configured Splunk Enterprise.
2. Collected Windows Security Event Logs.
3. Imported or forwarded security events into Splunk.
4. Used Splunk Search Processing Language (SPL) to search and filter events.
5. Analyzed successful and failed authentication attempts.
6. Investigated repeated login failures and potentially suspicious account activities.
7. Created a security monitoring dashboard to visualize event patterns.

### 5. Security Log Analysis

#### 5.1 Failed Login Attempts

**Objective:** Identify unsuccessful authentication attempts that could indicate unauthorized access attempts.

**SPL Query:**

```spl
index=main EventCode=4625
| table _time Account_Name EventCode
| sort -_time
```

**Observation:** Windows Event ID 4625 was used to identify failed login attempts. The account names and timestamps were examined to understand authentication failure patterns.

**Security Significance:** Multiple failed login attempts within a short period may indicate password guessing or brute-force activity.

#### 5.2 Successful Login Monitoring

**Objective:** Monitor successful user authentication events.

**SPL Query:**

```spl
index=main EventCode=4624
| table _time Account_Name EventCode
| sort -_time
```

**Observation:** Successful authentication events were identified and reviewed to understand normal login activity.

**Security Significance:** Monitoring successful logins helps identify unexpected account access and correlate successful authentication with previous failed attempts.

#### 5.3 Repeated Failed Login Detection

**Objective:** Identify accounts associated with multiple authentication failures.

**SPL Query:**

```spl
index=main EventCode=4625
| stats count by Account_Name
| sort -count
```

**Observation:** Failed login events were grouped by account name to identify accounts with higher authentication failure counts.

**Security Significance:** Accounts with repeated failures should be investigated further to determine whether the activity is accidental or potentially malicious.

#### 5.4 Potential Brute-Force Activity

**Objective:** Identify repeated failed login attempts associated with specific accounts and IP addresses.

**SPL Query:**

```spl
index=main EventCode=4625
| stats count by Account_Name, IpAddress
| where count >= 5
| sort -count
```

**Observation:** The query was designed to identify accounts and source IP addresses associated with five or more failed login attempts.

**Security Significance:** Repeated failures from the same source may indicate a possible brute-force attempt. Additional investigation is required before classifying the activity as malicious.

#### 5.5 New User Account Monitoring

**Objective:** Identify newly created user accounts.

**SPL Query:**

```spl
index=main EventCode=4720
| table _time Account_Name EventCode
```

**Observation:** Windows Event ID 4720 was used to identify user account creation events.

**Security Significance:** Unexpected account creation may indicate unauthorized account provisioning or privilege misuse.

#### 5.6 Security Log Clearing Detection

**Objective:** Identify events where the Windows Security audit log was cleared.

**SPL Query:**

```spl
index=main EventCode=1102
| table _time Account_Name EventCode
```

**Observation:** Security audit log clearing events were searched and reviewed.

**Security Significance:** Unexpected clearing of security logs may indicate an attempt to remove evidence of suspicious activity.

### 6. Key Investigation Findings

The following security indicators were examined during the investigation:

- Failed authentication attempts using Event ID 4625.
- Successful authentication events using Event ID 4624.
- Accounts with repeated login failures.
- Potential brute-force patterns involving repeated authentication failures.
- Newly created user accounts.
- Security audit log clearing events.

The analysis demonstrates how Splunk can centralize Windows security events and help analysts identify patterns that may require further investigation.

### 7. Security Recommendations

Based on the investigation objectives, the following security practices are recommended:

1. Implement strong password policies.
2. Enable account lockout policies to reduce repeated password guessing attempts.
3. Monitor failed login attempts and investigate unusual patterns.
4. Review unexpected user account creation events.
5. Monitor privileged account activity.
6. Protect security logs against unauthorized modification or deletion.
7. Configure alerts for suspicious authentication activity.
8. Regularly review security monitoring dashboards.

### 8. Conclusion

This project demonstrated the use of Splunk Enterprise for centralized security log monitoring and investigation.

By analyzing Windows Security Event Logs and developing SPL queries, the investigation covered authentication monitoring, repeated login failure detection, user account monitoring, and security audit log analysis.

The project provided practical exposure to SIEM operations, log analysis, threat detection, security event investigation, and dashboard creation.

It also demonstrated how security analysts can use centralized logging tools to improve security visibility and identify activities that may require further investigation.

### 9. Skills Demonstrated

- Splunk Enterprise
- Security Information and Event Management (SIEM)
- Splunk Search Processing Language (SPL)
- Windows Event Log Analysis
- Authentication Monitoring
- Brute-Force Detection
- Security Event Investigation
- Threat Detection
- Security Dashboard Creation
- Incident Documentation

---

**Note:** This report describes the investigation methodology and detection use cases. Populate the observations and findings with actual results from your Splunk environment before presenting it as a completed practical investigation. Do not report a security incident unless your collected logs support that conclusion.

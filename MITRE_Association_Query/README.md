# Kusto Query Language (KQL) Security Analysis Engine

## 1. Purpose

This document describes a Kusto Query Language (KQL) script designed to analyze Windows security event data. The primary function of the query is to identify, categorize, and report on system activities that may indicate security threats. It processes raw log data and organizes it according to the MITRE ATT&CK framework, a globally accessible knowledge base of adversary tactics and techniques.

## 2. Core Functionality

The query operates by performing a sequence of steps to transform complex event logs into understandable security insights.

### 2.1. User Configuration

The script begins with a configuration section where an analyst can define the scope of the investigation. The primary inputs include:
*   **Time Range:** The start and end times for the data analysis.
*   **Target Systems and Users:** Specific computers or user accounts to either include or exclude from the search.
*   **Event Type:** The specific categories of adversary tactics to investigate, based on the MITRE ATT&CK framework.
*   **Output Detail:** A selection that determines if the final report should be a high-level summary or a detailed list of all individual events.

### 2.2. Data Processing

After configuration, the query executes its main logic in three phases.

1.  **Event Filtering:** The query first selects a baseline of relevant events from the total set of security logs based on the specified time range, users, and systems.

2.  **Contextual Enrichment:** It enriches this raw data with additional context. The script maintains internal lookup tables to translate non-descriptive codes from the event logs into human-readable information.

3.  **Threat Categorization:** The query categorizes each relevant event according to its corresponding tactic and technique within the MITRE ATT&CK framework. It contains dedicated logic for different tactics.

## 3. Output

The final output of the query is a structured table of security-relevant activities. The user can select one of two output formats:

*   **Summarized View:** This mode groups together related events to provide a high-level overview. It shows what activity occurred, where it occurred, and the time range of the occurrences, preventing information overload by consolidating thousands of events into a few lines.

*   **Detailed View:** This mode provides an unabridged list of every single event that matched the search criteria, complete with its full event data. This is useful for in-depth forensic analysis where every detail is required.

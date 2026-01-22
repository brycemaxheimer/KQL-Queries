# KQL Unified Security Event Analysis Query
## Overview
This is an advanced Kusto Query Language (KQL) query designed to provide a unified and enriched view of security events from multiple sources within a Microsoft Sentinel environment. Its primary purpose is to normalize disparate log formats, particularly from Windows Security Auditing and Sysmon, into a single, consistent schema. The query is architected for modularity and scalability, allowing analysts to select and combine different event types for analysis without modifying the core query logic.

## Features
Unified Schema: Ingests and normalizes logs from different sources (SecurityEvent, Sysmon) into a single, predictable table structure.

Centralized Filtering: User-defined filters for time, systems, and accounts are configured in a single location and applied efficiently at the base of the query.

MITRE ATT&CK Enrichment: Automatically enriches events with corresponding MITRE ATT&CK Technique IDs, names, and tactics by cross-referencing a built-in datatable.

Dynamic Event Selection: Allows the analyst to specify which types of events to include in the query result (e.g., SystemAccess, FileAccess) through a single configuration variable.

Modular Architecture: The query is broken into logical, self-contained blocks for each event type, making it easy to maintain, debug, and extend with new event types in the future.

Robust Account Normalization: Intelligently parses account names from multiple potential fields (User, TargetUserName, SubjectUserName, Account) to create a single, reliable UnifiedAccount column, correctly handling both DOMAIN\User and standalone user formats.

## Architecture
The query is designed using a multi-stage, modular pattern to ensure efficiency and maintainability.

Configuration Block: At the top of the query, a series of let statements define all user-configurable parameters. This is the only section an analyst needs to interact with for day-to-day use.

MITR3Associations Datatable: A static datatable serves as a lookup dictionary to map combinations of EventID and EventSourceName to their corresponding MITRE ATT&CK framework details.

BaselineSecEvent View: This is the core of the query. It performs the initial data pull from the SecurityEvent table and applies all foundational filtering and enrichment.

Filters by time range.

Enriches events by performing a lookup against the MITR3Associations table.

Filters by specified and excluded systems.

Performs the crucial account normalization using coalesce() to create the UnifiedAccount field.

Filters by specified and excluded users based on the normalized UnifiedAccount.

Event-Specific Modules (let blocks): The query is divided into modular let statements, one for each EventType (e.g., FileOrObjectAccessEvents, SystemAccess).

Each module begins by filtering for its specific EventType, ensuring it only runs when selected by the user.

It then performs parsing and data manipulation specific to its event IDs.

It concludes by projecting a standardized set of columns to ensure its schema is compatible with all other modules.

union and project-reorder: The final stage unions the results from the executed modules and uses project-reorder to enforce a final, consistent column order for the output.

## Configuration
To use the query, modify the let statements in the top section.

EventType: A dynamic array specifying which modules to run (e.g., ["FileAccess", "SystemAccess"]).

SpecifiedSystem: A dynamic array of hostnames to include. An empty array [] includes all systems.

ExcludedSystem: A dynamic array of hostnames to exclude.

SpecifiedUser: A dynamic array of user accounts to include. An empty array [] includes all users.

ExcludedUser: A dynamic array of user accounts to exclude. Supports partial matching (e.g., "$" for machine accounts, "svc" for service accounts).

StartTime: The start of the query time range.

EndTime: The end of the query time range.

## Output Schema
The query produces a table with the following standardized columns:

| Column | Data Type | Description |
| TimeGenerated	| datetime | The timestamp of the event. |
| Computer | string | The name of the host where the event occurred. |
| UnifiedAccount | string | The normalized user or system account associated with the event. |
| EventID | int | The Windows Event ID. |
| AdditionalInformation | dynamic | An array containing context-specific data, such as file hashes or MITRE ATT&CK tactics. |
| MITR3Association | string | The associated MITRE ATT&CK Technique ID and name. |
| EventData | string | The original, raw event data, potentially reconstructed for clarity. |

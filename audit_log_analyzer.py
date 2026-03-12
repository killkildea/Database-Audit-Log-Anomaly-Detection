"""
Database Audit Log Anomaly Detection
Course: Secure Data: Mask, Monitor, and Audit
Module 2: Audit log anomaly detection - Core Application

This script analyzes database audit logs to detect unusual access patterns
and generate security alerts for potential threats.
"""

import pandas as pd
import numpy as np
from datetime import datetime, time


# PROVIDED CODE - DO NOT MODIFY
# Sample audit log data creation for testing
def create_sample_data():
    """Creates sample audit log data for analysis"""
    data = {
        'timestamp': [
            '2024-01-15 09:30:00', '2024-01-15 14:22:00', '2024-01-15 22:45:00',
            '2024-01-15 10:15:00', '2024-01-15 16:30:00', '2024-01-15 23:15:00',
            '2024-01-15 11:45:00', '2024-01-15 13:20:00', '2024-01-15 19:30:00',
            '2024-01-15 09:15:00', '2024-01-15 15:45:00', '2024-01-15 20:00:00',
            '2024-01-15 12:30:00', '2024-01-15 14:45:00', '2024-01-15 21:30:00'
        ],
        'user_id': [
            'alice_smith', 'bob_jones', 'charlie_brown', 'alice_smith', 'david_wilson',
            'charlie_brown', 'alice_smith', 'eve_davis', 'charlie_brown', 'bob_jones',
            'alice_smith', 'david_wilson', 'eve_davis', 'alice_smith', 'charlie_brown'
        ],
        'query': [
            'SELECT * FROM employees WHERE dept="HR"',
            'SELECT name, salary FROM salary_table WHERE employee_id=12345',
            'SELECT * FROM salary_table ORDER BY salary DESC LIMIT 100',
            'UPDATE employees SET phone="555-0123" WHERE id=67890',
            'SELECT avg(salary) FROM salary_table GROUP BY department',
            'SELECT * FROM salary_table WHERE salary > 150000',
            'INSERT INTO employees VALUES (99999, "New Employee", "IT")',
            'SELECT count(*) FROM employees WHERE status="active"',
            'SELECT user_id, salary FROM salary_table WHERE dept="EXEC"',
            'DELETE FROM temp_reports WHERE created < "2024-01-01"',
            'SELECT * FROM employees WHERE hire_date > "2023-01-01"',
            'SELECT max(salary), min(salary) FROM salary_table',
            'UPDATE employees SET manager_id=555 WHERE dept="SALES"',
            'SELECT name, salary, bonus FROM salary_table WHERE bonus > 10000',
            'SELECT * FROM salary_table WHERE employee_id IN (1,2,3,4,5,6,7,8,9,10)'
        ],
        'table_accessed': [
            'employees', 'salary_table', 'salary_table', 'employees', 'salary_table',
            'salary_table', 'employees', 'employees', 'salary_table', 'temp_reports',
            'employees', 'salary_table', 'employees', 'salary_table', 'salary_table'
        ]
    }

    return pd.DataFrame(data)


# Load the audit log data
print("Loading audit log data...")
audit_logs = create_sample_data()
print(f"Loaded {len(audit_logs)} audit log entries")

print("\nFirst few entries:")
print(audit_logs.head())


### PRACTICE CHALLENGE 1 ###
# TASK: Load the audit log data and create a new column that identifies 
# queries executed outside business hours (before 8 AM or after 6 PM)
# Convert `timestamp` to datetime and extract hour
audit_logs['timestamp'] = pd.to_datetime(audit_logs['timestamp'])
audit_logs['hour'] = audit_logs['timestamp'].dt.hour
# Flag queries outside business hours: before 8 AM (hour < 8) or after 6 PM (hour > 18)
audit_logs['outside_business_hours'] = audit_logs['hour'].apply(lambda h: (h < 8) or (h > 18))
print("\nQueries outside business hours:")
print(audit_logs[audit_logs['outside_business_hours']][['timestamp', 'user_id', 'table_accessed', 'query', 'hour']])
print(f"\nTotal outside-business-hours queries: {audit_logs['outside_business_hours'].sum()}")


### PRACTICE CHALLENGE 2 ###
# TASK: Calculate each user's salary query frequency and identify users 
# whose query count exceeds 2 standard deviations above the mean
# Identify salary-related queries (look for 'salary' in the SQL or access to `salary_table`)
salary_counts = audit_logs.groupby('user_id')['query'].apply(
    lambda s: s.str.lower().str.contains('salary').sum()
)
mean_count = salary_counts.mean()
std_count = salary_counts.std(ddof=0)
threshold = mean_count + 2 * std_count
outliers = salary_counts[salary_counts > threshold]
print("\nSalary-query counts per user:")
print(salary_counts.sort_values(ascending=False))
print(f"\nMean: {mean_count:.2f}, Std: {std_count:.2f}, Threshold (mean+2*std): {threshold:.2f}")
if not outliers.empty:
    print("\nUsers exceeding threshold (potential outliers):")
    print(outliers)
else:
    print("\nNo users exceed the salary-query frequency threshold.")

### PRACTICE CHALLENGE 3 ###
# TASK: Create a comprehensive security alert report that ranks anomalies 
# by risk level and includes specific recommendations for investigation
# Build multi-factor severity scoring
# Prepare helper data: mark users with high salary-query frequency
high_freq_users = set(salary_counts[salary_counts > threshold].index)

# Scoring weights (tunable)
TABLE_WEIGHTS = {'salary_table': 4, 'employees': 3, 'temp_reports': 1}
OP_WEIGHTS = {'DELETE': 3, 'UPDATE': 3, 'INSERT': 3, 'SELECT': 1}
OUTSIDE_HOURS_WEIGHT = 2
STAR_SELECT_WEIGHT = 1
HIGH_FREQ_USER_WEIGHT = 3

def compute_severity(row):
    score = 0
    table = row.get('table_accessed', '')
    score += TABLE_WEIGHTS.get(table, 0)

    # operation type
    try:
        op = row['query'].strip().split()[0].upper()
    except Exception:
        op = ''
    score += OP_WEIGHTS.get(op, 0)

    # SELECT * tends to be broader
    if '*' in row['query']:
        score += STAR_SELECT_WEIGHT

    # outside business hours
    if row.get('outside_business_hours'):
        score += OUTSIDE_HOURS_WEIGHT

    # high-frequency salary query user
    if row['user_id'] in high_freq_users:
        score += HIGH_FREQ_USER_WEIGHT

    return score

def score_to_level(score):
    if score >= 8:
        return 'Critical'
    if score >= 6:
        return 'High'
    if score >= 3:
        return 'Medium'
    return 'Low'

RECOMMENDATIONS = {
    'Critical': 'Immediate investigation: suspend account/session, collect query logs, and contact owner.',
    'High': 'Investigate: review user activity, recent changes, and verify business justification.',
    'Medium': 'Monitor and review: validate that access aligns with role and schedule.',
    'Low': 'Log and monitor: no immediate action required.'
}

# Compute scores for each audit row
alerts = audit_logs.copy()
alerts['severity_score'] = alerts.apply(compute_severity, axis=1)
alerts['risk_level'] = alerts['severity_score'].apply(score_to_level)
alerts['recommendation'] = alerts['risk_level'].map(RECOMMENDATIONS)

# Sort alerts by score descending and display summary
alerts_sorted = alerts.sort_values(by='severity_score', ascending=False)
print('\nAlert summary (top alerts by severity):')
print(alerts_sorted[['timestamp', 'user_id', 'table_accessed', 'query', 'severity_score', 'risk_level']].head(10))

print('\nCounts by risk level:')
print(alerts['risk_level'].value_counts())

print('\nRecommendations for top Critical/High alerts:')
print(alerts_sorted[alerts_sorted['risk_level'].isin(['Critical', 'High'])][['timestamp','user_id','table_accessed','query','severity_score','risk_level','recommendation']].head(10))


# PROVIDED CODE - DO NOT MODIFY
def display_summary():
    """Display analysis summary"""
    print("\n" + "=" * 50)
    print("AUDIT LOG ANALYSIS COMPLETE")
    print("=" * 50)
    print("Security monitoring analysis finished.")
    print("Review the alerts above for investigation priorities.")


# Call summary function at the end
display_summary()

import sqlite3

conn = sqlite3.connect('instance/hypertrust.db')
cursor = conn.cursor()
cursor.execute("SELECT COUNT(*) FROM resource_policies;")
count = cursor.fetchone()[0]
print(f"Resource policies count: {count}")

if count == 0:
    # Insert default policies
    policies = [
        ('research_data', 'Research Data Portal', 'Access to research datasets and academic publications', 'Academic', '📊', 'dept:cse or role:faculty'),
        ('confidential_docs', 'Confidential Documents', 'Internal documents and confidential materials', 'Administrative', '🔒', 'role:faculty'),
        ('computer_science', 'Computer Science Portal', 'CS department resources, labs, and materials', 'Department', '💻', 'dept:computerscience or role:faculty'),
        ('information_technology', 'IT Department Portal', 'IT resources, technical documentation, and support', 'Department', '🖥️', 'dept:informationtechnology or role:faculty'),
        ('electrical_engineering', 'Electrical Engineering Portal', 'EE labs, circuit designs, and technical resources', 'Department', '⚡', 'dept:electricalengineering or role:faculty'),
        ('mechanical_engineering', 'Mechanical Engineering Portal', 'ME design files, CAD resources, and project materials', 'Department', '⚙️', 'dept:mechanicalengineering or role:faculty'),
        ('civil_engineering', 'Civil Engineering Portal', 'Civil engineering plans, structural analysis, and resources', 'Department', '🏗️', 'dept:civilengineering or role:faculty'),
        ('business_administration', 'Business Administration Portal', 'Business resources, case studies, and administrative materials', 'Department', '💼', 'dept:businessadministration or role:faculty')
    ]

    cursor.executemany("""
        INSERT INTO resource_policies (resource_id, name, description, category, icon, policy)
        VALUES (?, ?, ?, ?, ?, ?)
    """, policies)
    conn.commit()
    print(f"Inserted {len(policies)} default resource policies.")

cursor.execute("SELECT resource_id, name, policy FROM resource_policies;")
rows = cursor.fetchall()
print("\nResource Policies:")
for row in rows:
    print(f"  {row[0]}: {row[1]} -> {row[2]}")

conn.close()
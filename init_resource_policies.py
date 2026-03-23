#!/usr/bin/env python3
"""
init_resource_policies.py — Initialize default resource policies
"""

import sqlite3
import os
import sys

# Add the current directory to the path so we can import our modules
sys.path.insert(0, os.path.dirname(__file__))

from db import get_db, save_resource_policy

def init_resource_policies():
    """Initialize default resource policies in the database"""

    # Default resource policies - payment is always required, admins can set additional attributes
    default_policies = [
        {
            "resource_id": "research_data",
            "name": "Research Data Portal",
            "description": "Access to research datasets and academic publications",
            "category": "Academic",
            "icon": "📊",
            "policy": "dept:cse or role:faculty"  # Will be ANDed with paid:true
        },
        {
            "resource_id": "confidential_docs",
            "name": "Confidential Documents",
            "description": "Internal documents and confidential materials",
            "category": "Administrative",
            "icon": "🔒",
            "policy": "role:faculty"  # Will be ANDed with paid:true
        },
        {
            "resource_id": "computer_science",
            "name": "Computer Science Portal",
            "description": "CS department resources, labs, and materials",
            "category": "Department",
            "icon": "💻",
            "policy": "dept:computerscience or role:faculty"  # Will be ANDed with paid:true
        },
        {
            "resource_id": "information_technology",
            "name": "IT Department Portal",
            "description": "IT resources, technical documentation, and support",
            "category": "Department",
            "icon": "🖥️",
            "policy": "dept:informationtechnology or role:faculty"  # Will be ANDed with paid:true
        },
        {
            "resource_id": "electrical_engineering",
            "name": "Electrical Engineering Portal",
            "description": "EE labs, circuit designs, and technical resources",
            "category": "Department",
            "icon": "⚡",
            "policy": "dept:electricalengineering or role:faculty"  # Will be ANDed with paid:true
        },
        {
            "resource_id": "mechanical_engineering",
            "name": "Mechanical Engineering Portal",
            "description": "ME design files, CAD resources, and project materials",
            "category": "Department",
            "icon": "⚙️",
            "policy": "dept:mechanicalengineering or role:faculty"  # Will be ANDed with paid:true
        },
        {
            "resource_id": "civil_engineering",
            "name": "Civil Engineering Portal",
            "description": "Civil engineering plans, structural analysis, and resources",
            "category": "Department",
            "icon": "🏗️",
            "policy": "dept:civilengineering or role:faculty"  # Will be ANDed with paid:true
        },
        {
            "resource_id": "business_administration",
            "name": "Business Administration Portal",
            "description": "Business resources, case studies, and administrative materials",
            "category": "Department",
            "icon": "💼",
            "policy": "dept:businessadministration or role:faculty"  # Will be ANDed with paid:true
        }
    ]

    # Create a minimal Flask app context to get database connection
    from flask import Flask
    app = Flask(__name__)
    app.config["DB_PATH"] = os.path.join(os.path.dirname(__file__), "instance", "hypertrust.db")

    with app.app_context():
        db = get_db()

        # Check if policies already exist
        existing = db.execute("SELECT COUNT(*) FROM resource_policies").fetchone()[0]
        if existing > 0:
            print(f"Resource policies already initialized ({existing} found). Skipping.")
            return

        # Insert default policies
        for policy in default_policies:
            save_resource_policy(
                db,
                policy["resource_id"],
                policy["name"],
                policy["description"],
                policy["category"],
                policy["icon"],
                policy["policy"]
            )

        db.commit()
        print(f"Initialized {len(default_policies)} default resource policies.")

if __name__ == "__main__":
    init_resource_policies()
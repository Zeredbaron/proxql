#!/usr/bin/env python3
"""
ProxQL + LangChain Demo: Watch an AI try to DROP TABLE and get blocked.

This demo simulates what happens when an LLM generates dangerous SQL.
No actual database or API keys needed - just shows the validation flow.

Run:
    pip install proxql
    python langchain_demo.py
"""

from __future__ import annotations

import proxql

# Simulated LLM responses - these are the kinds of queries an AI might generate
# when asked different questions about a database

SIMULATED_AI_QUERIES = [
    {
        "user_prompt": "How many users signed up last month?",
        "ai_sql": "SELECT COUNT(*) FROM users WHERE created_at > '2024-11-01'",
    },
    {
        "user_prompt": "Show me the top 10 products by revenue",
        "ai_sql": """
            SELECT p.name, SUM(o.amount) as revenue
            FROM products p
            JOIN orders o ON p.id = o.product_id
            GROUP BY p.id
            ORDER BY revenue DESC
            LIMIT 10
        """,
    },
    {
        "user_prompt": "Clean up the database to make it faster",
        "ai_sql": "DROP TABLE users; DROP TABLE orders; VACUUM;",  # 🔥 DANGEROUS
    },
    {
        "user_prompt": "Remove all inactive users",
        "ai_sql": "DELETE FROM users WHERE last_login < '2020-01-01'",  # 🔥 DANGEROUS
    },
    {
        "user_prompt": "Update the schema to add an email column",
        "ai_sql": "ALTER TABLE users ADD COLUMN email VARCHAR(255)",  # 🔥 DANGEROUS
    },
    {
        "user_prompt": "Get all user emails for the newsletter",
        "ai_sql": "SELECT email, name FROM users WHERE subscribed = true",
    },
]


def demo_read_only_mode():
    """Demonstrate read_only mode - only SELECT queries pass."""
    print("\n" + "=" * 60)
    print("🔒 MODE: read_only (default)")
    print("   Only SELECT queries are allowed")
    print("=" * 60)

    validator = proxql.Validator(mode="read_only")

    for scenario in SIMULATED_AI_QUERIES:
        result = validator.validate(scenario["ai_sql"])

        status = "✅ ALLOWED" if result.is_safe else "🚫 BLOCKED"
        print(f"\n📝 User asked: \"{scenario['user_prompt']}\"")
        print(f"🤖 AI generated: {scenario['ai_sql'].strip()[:60]}...")
        print(f"   {status}")
        if not result.is_safe:
            print(f"   Reason: {result.reason}")


def demo_table_allowlist():
    """Demonstrate table allowlist - even SELECT is restricted."""
    print("\n" + "=" * 60)
    print("🔐 MODE: read_only + table allowlist")
    print("   Only SELECT on [products, orders] allowed")
    print("=" * 60)

    validator = proxql.Validator(
        mode="read_only",
        allowed_tables=["products", "orders"],
    )

    test_queries = [
        ("SELECT * FROM products", "Product lookup"),
        ("SELECT * FROM users", "User lookup (not allowed!)"),
        ("SELECT * FROM products JOIN users ON products.user_id = users.id", "Join with users (caught!)"),
    ]

    for sql, description in test_queries:
        result = validator.validate(sql)
        status = "✅ ALLOWED" if result.is_safe else "🚫 BLOCKED"
        print(f"\n{description}")
        print(f"   SQL: {sql}")
        print(f"   {status}")
        if not result.is_safe:
            print(f"   Reason: {result.reason}")


def demo_integration_pattern():
    """Show how you'd integrate ProxQL in a real LangChain setup."""
    print("\n" + "=" * 60)
    print("🔧 INTEGRATION PATTERN")
    print("   How to wrap your database execution")
    print("=" * 60)

    print("""
# Your LangChain/agent code would look like this:

from langchain_community.utilities import SQLDatabase
from proxql import Validator

db = SQLDatabase.from_uri("postgresql://localhost/mydb")
validator = Validator(mode="read_only")

def safe_query(query: str) -> str:
    \"\"\"Execute a query only if it passes validation.\"\"\"
    result = validator.validate(query)
    if not result.is_safe:
        # Return error to the LLM so it can try again
        return f"ERROR: Query blocked - {result.reason}"
    return db.run(query)

# Then use safe_query() instead of db.run() in your agent
# The LLM will learn to avoid blocked patterns!
""")


def demo_benchmark():
    """Quick performance benchmark."""
    print("\n" + "=" * 60)
    print("⚡ PERFORMANCE")
    print("=" * 60)

    import time

    validator = proxql.Validator(mode="read_only")
    test_sql = "SELECT u.*, o.* FROM users u JOIN orders o ON u.id = o.user_id WHERE u.active = true"

    # Warm up
    for _ in range(100):
        validator.validate(test_sql)

    # Benchmark
    iterations = 10000
    start = time.perf_counter()
    for _ in range(iterations):
        validator.validate(test_sql)
    elapsed = time.perf_counter() - start

    per_query_us = (elapsed / iterations) * 1_000_000
    queries_per_sec = iterations / elapsed

    print(f"\n   Validated {iterations:,} queries in {elapsed:.3f}s")
    print(f"   ⏱️  {per_query_us:.1f} µs per query")
    print(f"   🚀 {queries_per_sec:,.0f} queries/second")


if __name__ == "__main__":
    print("\n" + "🛡️ " * 20)
    print("   ProxQL Demo: AI SQL Firewall")
    print("🛡️ " * 20)

    demo_read_only_mode()
    demo_table_allowlist()
    demo_integration_pattern()
    demo_benchmark()

    print("\n" + "=" * 60)
    print("✨ That's ProxQL! Install with: pip install proxql")
    print("   GitHub: https://github.com/zeredbaron/proxql")
    print("=" * 60 + "\n")


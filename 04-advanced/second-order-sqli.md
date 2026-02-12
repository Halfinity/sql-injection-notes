# Second-Order SQL Injection

Second-order SQL injection occurs when malicious input is stored in the database and later used in a SQL query in an unsafe manner.

## How It Works

### Phase 1: Storage (Safe)
```php
// Input is safely stored using prepared statements
$stmt = $conn->prepare("INSERT INTO users (username) VALUES (?)");
$stmt->bind_param("s", $_POST['username']);
$stmt->execute();
```

Username stored: `admin'--`

### Phase 2: Exploitation (Unsafe)
```php
// Later, the stored username is used unsafely
$username = $row['username']; // Retrieved from database: admin'--
$query = "UPDATE users SET email='$email' WHERE username='$username'";
// Vulnerable!
```

**Resulting Query:**
```sql
UPDATE users SET email='new@email.com' WHERE username='admin'--'
```

The password check is bypassed!

## Example Scenarios

### User Profile Update
1. User registers with username: `admin'); DROP TABLE users--`
2. Later, profile update query uses this username
3. Stored XSS or SQLi triggers

### Comment System
1. User posts comment: `' UNION SELECT password FROM admin--`
2. Admin views comments
3. Query executes with malicious input

## Detection

Second-order SQLi is harder to detect because:
- Initial input storage may be safe
- Exploitation happens later in application flow
- Requires understanding entire data flow
- Automated scanners often miss it

## Prevention

**✅ Always sanitize data from ALL sources:**
```php
// Even data from your own database!
$username = $row['username'];
$stmt = $conn->prepare("UPDATE users SET email=? WHERE username=?");
$stmt->bind_param("ss", $email, $username);
$stmt->execute();
```

## Key Takeaway

Never trust data, even from your own database - it may have been compromised!

---

**Remember: Only test on authorized systems!**

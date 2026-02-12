# How to Prevent SQL Injection

SQL injection is entirely preventable with proper coding practices. This guide covers the most effective prevention techniques.

---

## 🛡️ Primary Defense: Parameterized Queries (Prepared Statements)

The **#1 most effective** way to prevent SQL injection is using parameterized queries (also called prepared statements).

### What Are Parameterized Queries?

Parameterized queries separate SQL code from data. The database treats user input as data only, never as executable code.

### How They Work

**Vulnerable Code (String Concatenation):**
```java
String query = "SELECT * FROM products WHERE category = '" + input + "'";
Statement statement = connection.createStatement();
ResultSet resultSet = statement.executeQuery(query);
```

**Attack:**
```
input = "' OR '1'='1"
Final query: SELECT * FROM products WHERE category = '' OR '1'='1'
```

**Secure Code (Parameterized Query):**
```java
PreparedStatement statement = connection.prepareStatement(
    "SELECT * FROM products WHERE category = ?"
);
statement.setString(1, input);
ResultSet resultSet = statement.executeQuery();
```

**Attack Attempt:**
```
input = "' OR '1'='1"
Database treats this as the literal string "' OR '1'='1", not SQL code
Query becomes: SELECT * FROM products WHERE category = '\' OR \'1\'=\'1'
```

---

## 📚 Language-Specific Examples

### Java (JDBC)

```java
// ❌ VULNERABLE
String sql = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
Statement stmt = connection.createStatement();
ResultSet rs = stmt.executeQuery(sql);

// ✅ SECURE
String sql = "SELECT * FROM users WHERE username = ? AND password = ?";
PreparedStatement pstmt = connection.prepareStatement(sql);
pstmt.setString(1, username);
pstmt.setString(2, password);
ResultSet rs = pstmt.executeQuery();
```

### PHP (PDO)

```php
// ❌ VULNERABLE
$query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
$result = mysqli_query($connection, $query);

// ✅ SECURE
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->execute([$username, $password]);

// ✅ SECURE (Named parameters)
$stmt = $pdo->prepare("SELECT * FROM users WHERE username = :username AND password = :password");
$stmt->execute(['username' => $username, 'password' => $password]);
```

### PHP (MySQLi)

```php
// ❌ VULNERABLE
$query = "SELECT * FROM users WHERE username = '$username'";
$result = mysqli_query($conn, $query);

// ✅ SECURE
$stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
$stmt->bind_param("s", $username);
$stmt->execute();
$result = $stmt->get_result();
```

### Python (sqlite3)

```python
# ❌ VULNERABLE
cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")

# ✅ SECURE
cursor.execute("SELECT * FROM users WHERE username = ?", (username,))

# ✅ SECURE (Named parameters)
cursor.execute("SELECT * FROM users WHERE username = :username", {"username": username})
```

### Python (psycopg2 - PostgreSQL)

```python
# ❌ VULNERABLE
cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")

# ✅ SECURE
cursor.execute("SELECT * FROM users WHERE username = %s", (username,))
```

### C# (.NET)

```csharp
// ❌ VULNERABLE
string query = "SELECT * FROM users WHERE username = '" + username + "'";
SqlCommand command = new SqlCommand(query, connection);

// ✅ SECURE
string query = "SELECT * FROM users WHERE username = @username";
SqlCommand command = new SqlCommand(query, connection);
command.Parameters.AddWithValue("@username", username);
```

### Node.js (mysql2)

```javascript
// ❌ VULNERABLE
connection.query(`SELECT * FROM users WHERE username = '${username}'`, (err, results) => {
    // ...
});

// ✅ SECURE
connection.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
    // ...
});
```

### Ruby (ActiveRecord)

```ruby
# ❌ VULNERABLE
User.where("username = '#{username}'")

# ✅ SECURE
User.where("username = ?", username)

# ✅ SECURE (Hash conditions)
User.where(username: username)
```

---

## ⚠️ Limitations of Parameterized Queries

Parameterized queries **cannot** be used for:
- Table names
- Column names
- ORDER BY clause values
- LIMIT/OFFSET values (in some databases)
- SQL keywords

### Examples of What You CAN'T Parameterize

```sql
-- ❌ These don't work
SELECT * FROM ?                     -- Table name
SELECT ? FROM users                 -- Column name
SELECT * FROM users ORDER BY ?      -- Column name in ORDER BY
```

---

## 🔧 Additional Defense Techniques

### 1. Input Validation (Whitelist)

When you can't use parameterized queries, validate against a whitelist.

**Example: Dynamic Table Names**
```php
// ❌ VULNERABLE
$table = $_GET['table'];
$query = "SELECT * FROM $table";

// ✅ SECURE (Whitelist)
$allowed_tables = ['users', 'products', 'orders'];
$table = $_GET['table'];

if (in_array($table, $allowed_tables)) {
    $query = "SELECT * FROM $table";
    // Execute query
} else {
    die("Invalid table name");
}
```

**Example: ORDER BY Clause**
```python
# ❌ VULNERABLE
sort_column = request.GET['sort']
query = f"SELECT * FROM products ORDER BY {sort_column}"

# ✅ SECURE (Whitelist)
allowed_columns = ['name', 'price', 'date']
sort_column = request.GET['sort']

if sort_column in allowed_columns:
    query = f"SELECT * FROM products ORDER BY {sort_column}"
else:
    query = "SELECT * FROM products ORDER BY name"  # Default
```

### 2. Stored Procedures (When Parameterized)

```sql
-- Create stored procedure
CREATE PROCEDURE GetUserByUsername
    @username VARCHAR(50)
AS
BEGIN
    SELECT * FROM users WHERE username = @username
END

-- ✅ SECURE (Call from application)
```

```java
CallableStatement cstmt = connection.prepareCall("{call GetUserByUsername(?)}");
cstmt.setString(1, username);
ResultSet rs = cstmt.executeQuery();
```

**Warning:** Stored procedures are only secure if they use parameterized queries internally!

```sql
-- ❌ VULNERABLE stored procedure
CREATE PROCEDURE GetUser
    @username VARCHAR(50)
AS
BEGIN
    EXEC('SELECT * FROM users WHERE username = ''' + @username + '''')
    -- This is still vulnerable!
END
```

### 3. Escaping User Input (Last Resort)

Only use when parameterization is impossible. **Not recommended as primary defense.**

```php
// ⚠️ ESCAPING (better than nothing, but not ideal)
$username = mysqli_real_escape_string($conn, $_POST['username']);
$query = "SELECT * FROM users WHERE username = '$username'";
```

**Problems with escaping:**
- Easy to forget
- Database-specific
- Can be bypassed in some contexts
- Doesn't protect against all injection types

### 4. Least Privilege Principle

Limit database user permissions:

```sql
-- ❌ BAD: Application uses admin account
GRANT ALL PRIVILEGES ON database.* TO 'webapp'@'localhost';

-- ✅ GOOD: Application has minimal permissions
GRANT SELECT, INSERT, UPDATE ON database.users TO 'webapp'@'localhost';
-- No DROP, CREATE, DELETE permissions
```

**Benefits:**
- Limits damage from successful injection
- Prevents `DROP TABLE`, `DROP DATABASE`
- Prevents reading system tables
- Restricts file operations

### 5. Web Application Firewall (WAF)

Layer of defense that filters malicious requests.

**Example: ModSecurity Rules**
```
SecRule ARGS "@rx (\bUNION\b.*\bSELECT\b|\bOR\b.*=.*)" \
    "id:1,phase:2,deny,status:403,msg:'SQL Injection Attempt'"
```

**Limitations:**
- Can be bypassed
- May cause false positives
- Should not be sole defense
- Defense in depth, not replacement for secure coding

### 6. Regular Security Testing

```bash
# Automated scanning
sqlmap -u "http://example.com/page?id=1"

# Manual testing
# Test every input with:
'
"
\
' OR '1'='1
' UNION SELECT NULL--
```

---

## ✅ Complete Secure Example

```python
# Flask application with proper SQL injection prevention

from flask import Flask, request
import sqlite3
from functools import wraps

app = Flask(__name__)

def get_db():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

# Input validation decorator
def validate_input(allowed_values):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            for key, allowed in allowed_values.items():
                value = request.args.get(key) or request.form.get(key)
                if value and value not in allowed:
                    return "Invalid input", 400
            return f(*args, **kwargs)
        return wrapper
    return decorator

# ✅ SECURE: Parameterized query
@app.route('/user')
def get_user():
    username = request.args.get('username')
    conn = get_db()
    cursor = conn.cursor()
    
    # Parameterized query
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    
    return str(dict(user)) if user else "User not found"

# ✅ SECURE: Whitelist validation for ORDER BY
@app.route('/products')
@validate_input({'sort': ['name', 'price', 'date']})
def get_products():
    sort_by = request.args.get('sort', 'name')
    conn = get_db()
    cursor = conn.cursor()
    
    # Whitelist validated, safe to use
    cursor.execute(f"SELECT * FROM products ORDER BY {sort_by}")
    products = cursor.fetchall()
    conn.close()
    
    return str([dict(p) for p in products])

# ✅ SECURE: Multiple parameters
@app.route('/search')
def search():
    category = request.args.get('category')
    min_price = request.args.get('min_price', 0)
    max_price = request.args.get('max_price', 99999)
    
    conn = get_db()
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT * FROM products 
        WHERE category = ? 
        AND price BETWEEN ? AND ?
    """, (category, min_price, max_price))
    
    products = cursor.fetchall()
    conn.close()
    
    return str([dict(p) for p in products])

if __name__ == '__main__':
    app.run()
```

---

## 📋 Prevention Checklist

### Before Deployment

- [ ] All queries use parameterized statements
- [ ] Table/column names validated against whitelist
- [ ] Database user has minimal privileges
- [ ] Input validation on all user inputs
- [ ] Error messages don't reveal DB structure
- [ ] Security testing completed (manual + automated)
- [ ] WAF configured (if applicable)
- [ ] Code review completed
- [ ] Logging and monitoring in place

### During Development

- [ ] Never concatenate user input into queries
- [ ] Use ORM frameworks properly
- [ ] Validate all inputs (client and server-side)
- [ ] Don't trust any external data
- [ ] Test for SQLi on all input points
- [ ] Document why any non-parameterized queries exist

---

## 🚨 Common Mistakes

### 1. Partial Parameterization

```python
# ❌ STILL VULNERABLE
cursor.execute(f"SELECT * FROM {table} WHERE username = ?", (username,))
#               ^^^^^^^^ Not parameterized!
```

### 2. Trusting Internal Data

```php
// ❌ VULNERABLE (data from database can be compromised)
$admin_name = $row['admin_name'];  // From database
$query = "UPDATE users SET role='user' WHERE username != '$admin_name'";
```

### 3. Client-Side Validation Only

```javascript
// ❌ INSUFFICIENT (client-side validation can be bypassed)
if (!/^[a-zA-Z0-9]+$/.test(username)) {
    alert("Invalid username");
    return;
}
// Must also validate server-side!
```

### 4. Blacklist Filtering

```php
// ❌ INEFFECTIVE (easily bypassed)
$input = str_replace("'", "", $input);
$input = str_replace("OR", "", $input);
$input = str_replace("UNION", "", $input);
// Attacker can use: ' OORR '1'='1
```

---

## 🎯 Key Takeaways

1. **Always use parameterized queries** for user data
2. **Whitelist validation** for elements that can't be parameterized
3. **Principle of least privilege** for database accounts
4. **Defense in depth** - multiple layers of security
5. **Never trust any external input** - including cookies, headers
6. **Test thoroughly** - both manual and automated
7. **ORM frameworks** help but aren't foolproof
8. **Escaping is not sufficient** - use parameterization

---

## 📚 Further Reading

- [OWASP SQL Injection Prevention Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html)
- [CWE-89: SQL Injection](https://cwe.mitre.org/data/definitions/89.html)
- [Bobby Tables: A guide to preventing SQL injection](https://bobby-tables.com/)

---

**Remember: Prevention is always better than detection!**

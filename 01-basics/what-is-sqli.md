# What is SQL Injection?

## Definition

SQL Injection (SQLi) is a web security vulnerability that allows an attacker to interfere with the queries that an application makes to its database. It generally allows an attacker to view data that they are not normally able to retrieve, modify database data, or execute administrative operations on the database.

## How SQL Injection Works

SQL injection attacks work by exploiting insufficient input validation in web applications. When user input is directly concatenated into SQL queries without proper sanitization, attackers can inject malicious SQL code.

### Example Scenario

Consider a simple login form that checks credentials with this query:

```sql
SELECT * FROM users WHERE username = 'USER_INPUT' AND password = 'USER_INPUT'
```

If an attacker inputs `admin'--` as the username, the query becomes:

```sql
SELECT * FROM users WHERE username = 'admin'--' AND password = ''
```

The `--` comment symbol causes the password check to be ignored, potentially allowing authentication bypass.

## Impact of SQL Injection

SQL injection vulnerabilities can have severe consequences:

### 1. **Unauthorized Data Access**
- Retrieve sensitive information (passwords, credit cards, personal data)
- Access records belonging to other users
- View confidential business data

### 2. **Data Modification**
- Modify or delete database records
- Insert malicious data
- Change user privileges

### 3. **Database Server Compromise**
- Execute administrative operations
- Read/write files on the database server
- Potentially gain remote code execution

### 4. **Denial of Service**
- Corrupt database integrity
- Delete critical data
- Overload the database server

## Common Vulnerable Scenarios

### 1. Search Functionality
```sql
SELECT * FROM products WHERE name LIKE '%USER_INPUT%'
```

### 2. Login Forms
```sql
SELECT * FROM users WHERE username = 'USER_INPUT' AND password = 'USER_INPUT'
```

### 3. Sorting/Filtering
```sql
SELECT * FROM products WHERE category = 'USER_INPUT' ORDER BY price
```

### 4. URL Parameters
```
https://example.com/products?id=5
SELECT * FROM products WHERE id = 5
```

## Why SQL Injection is Critical

1. **Widespread**: Affects applications using any SQL database
2. **Easy to Exploit**: Basic attacks require minimal technical knowledge
3. **High Impact**: Can lead to complete database compromise
4. **Often Overlooked**: Developers may not implement proper defenses
5. **Automated Tools**: Attackers can use automated scanners to find vulnerabilities

## Real-World Example

### Vulnerable Code (PHP):
```php
$username = $_POST['username'];
$password = $_POST['password'];

$query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
$result = mysqli_query($connection, $query);
```

### Attack:
Input: `username = admin'--` and `password = anything`

Result: Authentication bypass

## Prevention Preview

The primary defense against SQL injection is **parameterized queries** (prepared statements):

```php
$stmt = $connection->prepare("SELECT * FROM users WHERE username = ? AND password = ?");
$stmt->bind_param("ss", $username, $password);
$stmt->execute();
```

## Key Takeaways

- SQL injection occurs when user input is improperly handled in SQL queries
- It can lead to unauthorized access, data theft, and database compromise
- It's one of the most critical web application vulnerabilities
- Proper input validation and parameterized queries are essential defenses

## Next Steps

- Learn about [Types of SQL Injection](types-of-sqli.md)
- Understand [Common Locations](common-locations.md) where SQLi occurs
- Study [Exploitation Techniques](../02-exploitation/)

---

**Remember**: Always test for SQL injection only on systems you have permission to test!

Host: SimCorp Web App Event Log Analysis

Query Used:

(index="main" host="10.0.0.175"
This initial query is very broad and searching for suspicious activitiy in the SimCorp Web App (10.0.0.175):
index="main" host="ip-10-0-0-175"

![Screenshot 2024-07-03 at 10 34 41 PM](https://github.com/TrollTrace/TrollTrace/assets/34401677/9c12304f-60be-4442-88b9-5c7a1f604e4f)


The query returns over 40,000 events so further refinement is needed.  The search was narrowed down with a source path where "/var/log/apache2/access.log" has clearly had the bulk of events:

![var:log filter](https://github.com/TrollTrace/TrollTrace/assets/34401677/66ff5370-2869-4322-91a7-3d2dac3e1e04)


So the investigation continued with this query:
index="main" host="ip-10-0-0-175" source="/var/log/apache2/access.log"

This was the result:

![Somewhat suspicious](https://github.com/TrollTrace/TrollTrace/assets/34401677/f83328de-ef7d-4525-bf18-aa51b7a4bf5e)

These first 3 logs are suspicious and they are a good representative of all in this category.

The first log entry shows an attempt to access the /etc/passwd file using a URL encoding technique which could be indicative of an SQL injection attack.
Request: GET /cgi-bin/.%32%65/.%32%65/.%32%65/.%32%65/etc/passwd
Status Code: 400 (Bad Request)
User-Agent: iPad, Mac OS X
Suspicious Aspect: The request is attempting to access /etc/passwd, which is a sensitive system file in Unix-like systems. The use of encoded characters (%32%65) indicates an attempt to bypass security filters.

The second log entry is also suspicious.
Request: \x16\x03\x03\x01\x02
Status Code: 400 (Bad Request)
User-Agent: None
Suspicious Aspect: This entry shows a binary request (likely an SSL/TLS handshake attempt) sent to a web server port, which is unusual if it’s not an HTTPS server. 
This could indicate a port scanning or a probing attempt.

The third log entry is an attempt to find other weaknesses and is enough to continue the search.
Request: GET /simcorp/login.php
Status Code: 200 (OK)
User-Agent: Windows NT, Chrome
Suspicious Aspect: Access to a login page (/simcorp/login.php). While this by itself is not suspicious, in the context of the other entries, it could indicate an attempt to find login portals for potential attacks.

The investigation continued and uncovered these logs as well:

![Highly suspicious](https://github.com/TrollTrace/TrollTrace/assets/34401677/84390da1-83f3-4716-b35e-29bf32eedc1c)


The logs here are highly suspicious and indicate attempts at SQL injection attacks.  One major tip-off is the .php file named "/var/www/html/sqli_1.php"  SQLI meaning Structured Query Language Injection.

![SQLI](https://github.com/TrollTrace/TrollTrace/assets/34401677/091e9286-55d2-4934-9a11-b6b94a4ed973)


* Repeated Access Attempts:
All the log entries show repeated attempts to access sqli_1.php with different payloads (GET /sqli_1.php?id=1%29%20ORDER%20BY%207003--%20dHOS), which is a clear indicator of automated testing or an attack.
The payload tries to use ORDER BY with an arbitrary number, which is a common technique in SQL injection to test for vulnerabilities.

* User-Agent:
The User-Agent in all entries is sqlmap/1.8.5#stable (https[1]://sqlmap.org). SQLMap is a well-known tool used for automated SQL injection and database takeover.

* Request Patterns:
The URLs contain SQL injection payloads, attempting to manipulate SQL queries through URL parameters.
For example, the payloads contain encoded characters, SQL keywords, and commands such as ORDER BY and various encoded string manipulations designed to exploit vulnerabilities in the application.
Attempts were executed to use a more complex payload involving DBMS_PIPE.RECEIVE_MESSAGE.
The repeated requests with similar payloads indicate a brute force approach to identify a working SQL injection vector.

The immediate actions to take (were this not an exercise) would be to:
* Block the IP address 10.0.0.176 if it’s not a known or trusted source.
* Review your web application's code and database queries to ensure they are secure against SQL injection (e.g., use prepared statements, parameterized queries).
* Implement Web Application Firewalls (WAF) to detect and block SQL injection attempts.
* Regularly update and patch your web applications and underlying frameworks.
* Perform security audits and penetration testing to identify and fix vulnerabilities.



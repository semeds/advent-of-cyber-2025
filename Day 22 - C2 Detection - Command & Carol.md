# Day 22: C2 Detection - Command & Carol
Here is the link to the [room](https://tryhackme.com/room/detecting-c2-with-rita-aoc2025-m9n2b5v8c1)

### Purpose of the room:
How to detect command and control (C2) traffic in network captures using Zeek and RITA, and know how to interpret the results

### Learning Objectives:
- Understand what C2 traffic looks like in real network data
- Convert a PCAP to Zeek logs
- Use RITA to analyze Zeek logs
- Analyze the output of RITA

**Zeek** - open-source network security monitoring tool (NSM), solely observes network traffic via configured SPAN ports (used to copy traffic from one port to another for monitoring), physical network taps, or imported packet captures in the PCAP format
## Understanding PCAP files, Zeek logs and RITA ouput
### Converting PCAP files to Zeek logs
First step we're going to take is use Zeek to parse some pcap logs.
To list contents of the current directory, use the command `ls`. The output should resemble the following:

![](attachments/Pasted%20image%2020251223222013.png)

We are currently focused on the `zeek_logs` and `pcaps` folders.
`pcaps` contains real-life incidents collected from Bradly Duncan's [blog](https://malware-traffic-analysis.net/) 
`zeek_logs` contains Zeek logs that are already parsed PCAP files

To parse a PCAP file ourselves we can use this command:
`zeek readpcap <pcapfile> <outputdirectory>`

In the terminal type `zeek readpcap pcaps/AsyncRAT.pcap zeek_logs/asyncrat`
![](attachments/Pasted%20image%2020251223222648.png)

To examine the logs, let's use the command `cd /home/ubuntu/zeek_logs/asyncrat && ls`
This navigates to the `asyncrat` folder in `zeek_logs` and list its contents:

![](attachments/Pasted%20image%2020251223222815.png)

If you want, you can see the contents of each file using `cat <file-name>`

### Log Analysis using RITA
Now we will perform some log analysis using the RITA tool
The command to type in the terminal is this: 
`rita import --logs ~/zeek_logs/asyncrat/ --database asyncrat`

Once done, you should have a lot of output in the terminal that resembles this: 
![](attachments/Pasted%20image%2020251223223806.png)

According to TryHackMe: "It is important to consider the dataset's size. Larger datasets will provide more insights than smaller ones. Smaller datasets are also more prone to false positive entries. The one we are using is rather small, but it contains sufficient data for an initial usable result."


To view results from RITA output, we use the command `rita view <database-name>`
So in this lab we'd type `rita view asyncrat` in the terminal, and we get the resulting terminal window:
![](attachments/Pasted%20image%2020251223224350.png)

We can see a search bar, results pane, and details pane

#### Search bar
We need to use a forward slash to `/` to start a search,  then we can enter our search terms
Typing a question mark `?` in search mode gives us an overview of the search fields:
![](attachments/Pasted%20image%2020251223224701.png)

To exit the help page, we press `?` again
Press the escape key to exit search functionality

#### Results pane
The results pane includes information for each entry that can quickly help us recognize potential threats. The following columns are included:
- **Severity**: A score calculated based on the results of threat modifiers (discussed below)
- **Source and destination** IP/FQDN
- **Beacon** likelihood
- **Duration** of the connection: Long connections can be indicators of compromise. Most application layer protocols are stateless and close the connection quickly after exchanging data (exceptions are SSH, RDP, and VNC).
- **Subdomains**: Connections to subdomains with the same domain name. If there are many subdomains, it could indicate the use of a C2 beacon or other techniques for data exfiltration.
- **Threat intel**: lists any matches on threat intel feeds

We have two findings, one being an FQDN (Fully Qualified Domain Name) `sunshine-bizrate-inc-software[.]trycloudflare[.]com` and an IP `91[.]134[.]150[.]150`. Use the arrow keys to move between them, and see what the results pane says about each of them.

#### Details pane
Apart from the Source and Destination, we have two information categories: Threat Modifiers and Connection info. Let's have a closer look at these categories:

_Threat Modifiers_  
These are criteria to determine the severity and likelihood of a potential threat. The following modifiers are available:

- **MIME type/URI mismatch:** Flags connections where the MIME type reported in the HTTP header doesn't match the URI. This can indicate an attacker is trying to trick the browser or a security tool.
- **Rare signature:** Points to unusual patterns that attackers might overlook, such as a unique user agent string that is not seen in any other connections on the network.
- **Prevalence:** Analyzes the number of internal hosts communicating with a specific external host. A low percentage of internal hosts communicating with an external one can be suspicious.
- **First Seen:** Checks the date an external host was first observed on the network. A new host on the network is more likely to be a potential threat.
- **Missing host header:** Identifies HTTP connections that are missing the host header, which is often an oversight by attackers or a sign of a misconfigured system.
- **Large amount of outgoing data**: Flags connections that send a very large amount of data out from the network.
- **No direct connections:** Flags connections that don't have any direct connections, which can be a sign of a more complex or hidden command and control communication.

_Connection Info_  
Here, we can find the connections' metadata and basic connection info like:

- Connection count: Shows the number of connections initiated between the source and destination. A very high number can be an indicator of C2 beacon activity.
- Total bytes sent: Displays the total amount of bytes sent from source to destination. If this is a very high number, it could be an indication of data exfiltration.
- Port number - Protocol - Service: If the port number is non-standard, it warrants further investigation. The lack of SSL in the Service info could also be an indicator that warrants further investigation.


### Log Analysis Contd.
The long FQDN is the first thing that stands out: `sunshine-bizrate-inc-software[.]trycloudflare[.]com`. Using VirusTotal to perform a search, it shows the URL is flagged as malicious
![](attachments/Pasted%20image%2020251223225958.png)

The details pane also includes the `rare signature` threat modifier, indicating a combination of certain parameters (e.g. SSL certificate details) related to the connection are unusual compared to the rest of the analyzed HTTPS traffic. Malware or C2 connections tend to create unique TLS handshake patterns that differ from those of browsers and legitimate clients, so they stand out even if the payload is encrypted

Looking at the second entry:
- We have a malicious IP

![](attachments/Pasted%20image%2020251223230502.png)

- Connection duration is long
- We have some ports that aren't typically used

Now we have some basic knowledge of how to use Zeek to parse PCAP files, and also how to interpret RITA output.

## Practical
We will be answering the questions by analyzing `~/pcaps/rita_challenge.pcap` with RITA.

### Step 1: File conversion
First step is converting the PCAP file to a Zeek log. Click [converting PCAP to Zeek](#Converting%20PCAP%20files%20to%20Zeek%20logs) to refer back to how convert these.

Use the command `zeek readpcap pcaps/rita_challenge.pcap zeek_logs/rita_challenge`
![](attachments/Pasted%20image%2020251223231927.png)

Now we can check the `zeek_logs` folder to ensure successful conversion and lists the contents of the new `rita_challenge` folder.
cd into the newly created folder `cd /home/ubuntu/zeek_logs/rita_challenge && ls`
![](attachments/Pasted%20image%2020251223232115.png)

### Step 2: RITA Analysis
Now we can import this folder into RITA for analysis using the command
`rita import --logs ~/zeek_logs/rita_challenge --database rita_challenge`
Expected terminal output:
![](attachments/Pasted%20image%2020251223232612.png)

*Notes:* 
- If you have another instance of RITA running, you will be unable to import a new folder into RITA. First close the instance you are not using, then try the import again
- Take care when naming the new database. RITA doesn't accept certain characters such as hyphens. It will throw an error and no database will be exported
![](attachments/Pasted%20image%2020251223232744.png)

Now we can view the database using `rita view rita_challenge`, and this will open up a new instance of RITA with the new logs
![](attachments/Pasted%20image%2020251223232901.png)

We are now in a good position to answer the questions. For each question, all we have to do is go through the logs carefully and know exactly what we're looking for.

1. "How many hosts are communicating with **malhare.net**?"
	Just count the number of destination FQDNs that contain `malhare.net`

2. Which Threat Modifier tells us the number of hosts communicating to a certain destination?
	This can be found under the *Threat Modifiers* criteria in the detail pane
	
3. What is the highest number of connections to **rabbithole.malhare.net**?
	To get this, we can look at the *Connection Count* under *Connection Info* in the details pane
	
4. Which search filter would you use to search for all entries that communicate to **rabbithole.malhare.net** with a **beacon score** greater than 70% and sorted by **connection duration (descending)**?
	If you can't recall how to get to the search bar, click [getting to search bar](#Search%20bar). You'll notice that there example searches for both single and multiple criteria. Construct the proper search filter to get the desired results

5. Which port did the host 10.0.0.13 use to connect to **rabbithole.malhare.net**?
	Answer should be under the `Port : Proto : Service` heading under *Connection Info*

# Phishing-Analysis

## Objective

Perform a full start-to-finish investigation of two malicious emails, from gathering artifacts all the way through to writing a clear report of the steps you have taken, and the defensive measures you would like to take.

### Skills Learned

- Demonstrate your ability to determine if emails are malicious or not based on experience and judgment.
- Demonstrate your ability to correctly categorize malicious emails based on context and artifact analysis.
- Conduct a full phishing investigation including detection, triage, and report writing stages.
- Correctly suggest appropriate defensive measures based on artifact analysis.

### Tools Used

- WHOIS lookup for reverse DNS.
- VirusTotal to analyze files and URLs for potential malware and other security threats. 
- URL2PNG to take screenshots of web pages without visiting the webpage itself.
- Wannabrowser to view the source code of a website without browsing it.

## Steps

An analyst sends us two emails that appear to be malicious. It is our job to determine whether these emails are malicious or not.


### Email One
![image](https://github.com/CristianFernandez123/Phishing-Analysis/assets/161634608/37ec8486-d572-4362-8964-305ae0f2e863)

#### Some initial key points I have analyzed
- Fonts are not consistent like real Amazon emails.

- The email isn't directed at a specific person just an "Amazon user."

- Email has poor grammar like ‘Your ID’ (should be your account), and ‘From Amazon Store.’

- Email is enticing users to click on the link for the 'Help Page - Refund Form.'


#### Artifact Extraction

Opening Email One in Sublime Text and searching for (CTRL+F) ‘From’ we can find the sending email address, which is contained within the <> symbols at the end of the line 

![image](https://github.com/CristianFernandez123/Phishing-Analysis/assets/161634608/8f810aef-4616-4a88-8707-57239335f22b)

Searching for ‘Subject’ we can find the subject line.

![image](https://github.com/CristianFernandez123/Phishing-Analysis/assets/161634608/bd72a325-3d92-4c7f-86b6-25acee5c10e0)

Searching for 'To:' we can see the email is being sent to jack.tractive@abcindustries.co.uk.

![image](https://github.com/CristianFernandez123/Phishing-Analysis/assets/161634608/4b69b970-e412-4b0a-ab6f-81dc698266c7)

Searching for ‘Date’ will show us the timestamp of the email.

![image](https://github.com/CristianFernandez123/Phishing-Analysis/assets/161634608/b8dc9473-0fcb-4297-bee3-8a39b211ea0a)

Searching for ‘Sender’ we can see several references to the same IP address, including a mention of SPF checks that came back positive for this IP.

![image](https://github.com/CristianFernandez123/Phishing-Analysis/assets/161634608/36584682-3ac9-43d7-bc38-bb3c47a4572e)

Now we can perform a reverse DNS on the sender IP 68.114.190.29, we do this on https://whois.domaintools.com/. The website states the IP is owned by  ‘United States Ashburn Charter Communications’ which means the IP isn't associated with an individual entity. Thankfully the email always preserves the hostname in its files.

Searching for the IP 68.114.190.29 in sublime we can find the hostname of the sending server.

![image](https://github.com/CristianFernandez123/Phishing-Analysis/assets/161634608/484b428e-d14b-4587-baad-ecae58eef5e3)

We can now get the full URL by right-clicking the hyperlink in the email and selecting 'copy link location.' We can take this link and perform further analysis to determine if it's a malicious site or not. Using https://www.url2png.com/ we can get a view of the webpage without actually visiting the malicious site. In this case, the link led to a fake website impersonating Amazon, being used as a Credential Harvester. 

![image](https://github.com/CristianFernandez123/Phishing-Analysis/assets/161634608/5ee91ab6-0ecb-452a-9925-cec7add66669)


### Email Two
![image](https://github.com/CristianFernandez123/Phishing-Analysis/assets/161634608/51c2aa52-6ada-40aa-9f61-870bbcc8d5ca)

With Email Two I can get all the artifacts by repeating the same steps as I did with Email one. The difference with email two is that there is an attachment that can possibly be malicious. I will extract the SHA256 Hash of the attachment and use it to investigate further. If we were dealing with a real malicious attachment then we would want to download it within a virtual machine (that is only used for analysis and doesn't hold corporate data) and hash the file using PowerShell or Linux CLI.

I don't have access to the malicious executable that was stored in the email anymore but I can provide a screen shot of the hash and file name.
![image](https://github.com/CristianFernandez123/Phishing-Analysis/assets/161634608/7d6858be-7048-4f97-b2ec-eb7ae1392c48)

I retrieved the hash by opening PowerShell where the file was downloaded to and use the command "Get-FileHash .\COVID19-Testing-Kit-2020.pdf.exe."

This returns the SHA256 hash by default which we can copy and paste into [virustotal.com](https://www.virustotal.com/gui/home/upload) to see if we have a malicious attachment or not. It is important to note just because VirusTotal comes out as not malicious doesn't mean the file isn't malicious and further analysis would have to be done. In this case, we got the malicious tags on VirusTotal. 

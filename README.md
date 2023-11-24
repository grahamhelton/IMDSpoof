# IMDSPOOF
IMDSPOOF is a cyber deception tool that spoofs an AWS IMDS service. One way that attackers are able to escalate privileges or move laterally in a cloud environment is by retrieving AWS Access keys from the [IMDS service](https://hackingthe.cloud/aws/exploitation/ec2-metadata-ssrf/) endpoint located at `http://169.254.169.254/latest/meta-data/iam/security-credentials/<user>`. This tool spoofs that endpoint and redirects traffic sent to `169.254.169.254` to a local webserver that serves fake data. This can be leveraged for highly tuned detections by inserting [honey AWS tokens]() (Insert Reference) into the response of the spoofed IMDS response.

![IMDSPOOF.png](./IMDSPOOF.png)

# Who is this for?
This tool is intended to be used by blue teams on AWS instances that are *NOT* actively using the IMDS (version 1 or 2). 

From an attacker's perspective, they have no idea if the IMDS is being used on the EC2 instance they're in. The goal of IMDSPOOF is to trick an attacker who lands in your cloud environment into thinking that they're interacting with a legitimate IMDS service. 

# ⚠️ Warning ⚠️
Once again, if the applications running on your EC2 instance ARE using the IMDS service, this tool WILL cause issues!

# Try it out
To try out IMDSPOOF in a test environment, create an EC2 instance and make sure iptables is installed (`yum install iptables-services` if using amazon linux) 
- Compile and run `IMDS.go` ([How To Compile Go Code](https://go.dev/doc/tutorial/compile-install))
- To test out what the output looks like, run `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-admin`
- You should see the following output:
```bash
{
  "Code": "Success",
  "Message": "The request was successfully processed.",
  "LastUpdated": "2023-11-22T03:33:51Z",
  "Type": "AWS-HMAC",
  "AccessKeyId": "InsertHoneyToken",
  "SecretAccessKey": "InsertHoneyToken",
  "Token": "HoneyToken",
  "Expiration": "2023-11-22T09:33:51Z"
}

```
- To revert changes from the previous IP tables command run the following  `iptables -t nat -D OUTPUT -p tcp -d 169.254.169.254 --dport 80 -j DNAT --to-destination 127.0.0.1:54321`


# Customization
In order for this to be useful, you must change the variables at the top of the `IMDS.go` file to be something more real looking. I *highly* recommend placing honey tokens in the file. You can leave the `token` variable alone or change it to a custom one.

- Change these variables at the top of `IMDS.go` to whatever you want returned from accessing `http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-admin`
```go
var accessKey string = "InsertHoneyToken"
var secretAccessKey string = "InsertHoneyToken"
var token string = "IQoJb3Jpz2cXpQRkpVX3Uf////////////xMdLZHNjb<snip>"
```

# Getting HoneyTokens
The folks over at [Thinkst Canary](https://canary.tools/) have a [wonderful tool](https://canarytokens.org/generate#) that allows you to easily generate AWS credentials that will generate an alert on usage.
1. Visit [CanaryTokens](https://canarytokens.org/generate#)
2. Select *AWS Keys*, enter an email for the alert to go to and a note for what the alert is for
![Pasted image 20231124171011.png](./Pasted image 20231124171011.png)
3. Note down the honeytoken provided 
```bash
aws_access_key_id = AKIA....
aws_secret_access_key = uZF0y/l5X....
```
4. Within the IMDS.go source code, replace the `accessKey` and `secretAccessKey` variable's with the `aws_access_key_id` and `aws_secret_access_key` values given to you by CanaryTokens.

![Pasted image 20231124171422.png](./Pasted image 20231124171422.png)

5. Compile IMDS.go. IMDS will now return the honey tokens when the IMDS is queried. 

![Pasted image 20231124172134.png](./Pasted image 20231124172134.png)

6. Wait for an attacker to attempt to use the credentials

![Pasted image 20231124172935.png](./Pasted image 20231124172935.png)

7. Email alert from Canary Token

![Pasted image 20231124173123.png](./Pasted image 20231124173123.png)




# Run at startup 
Running IMDS spoof at startup can be done easily by create a systemd service and enabling the service.


- Create a file at service file `sudo vim /etc/systemd/system/IMDS.service` (You can name this something else more stealthy if you wish but the following `systemctl` commands expect the service to be named `IMDS.service`)
- Add the following to the `IMDS.service` file just created

```bash
[Unit]
# Change this to something else if you wish
Description=IMDSPOOF 

# After dependencies are available
After=multi-user.target

[Service]
# Type of service
Type=simple

# Command to execute the service program
ExecStart=/bin/IMDS

# User to run the service as
User=root

# Restart if the service crashes
Restart=always

# Restart delay in seconds
RestartSec=10

[Install]
# Enable the service at boot
WantedBy=multi-user.target
```

- Make sure the IMDS binary is in the `/bin/` directory: `sudo mv IMDS /bin/`
- Enable the service to start at boot `sudo systemctl enable IMDS`
- Start the service now `sudo systemctl start IMDS`
- Ensure everything is running correctly with `sudo systemctl status IMDS`
# Does this work with SSRF?
Yes! Because of the way IMDSpoof manipulates the iptables on the ec2 instance, it doesn't matter where the traffic is coming from. This means that in addition to this working via the curl utilitiy on the EC2 instance, IMDSpoof also works if an SSRF vulnerability is found through a web application hosted on the EC2 instance. Using the following [vulnerable application from AlexanderHose's blog](https://alexanderhose.com/how-to-hack-aws-instances-with-the-metadata-service-enabled/) on IMDS pentesting, we can exploit the SSRF vulnerability which will also return the fake credentials from IMDSpoof
![Image](./Pasted image 20231124180610.png)

# Reverting
- To stop the systemd service: `sudo systemctl stop IMDS`
- To stop the systemd service from running at startup: `sudo systemctl disable IMDS`
- To revert changes IMDSPOOF makes to iptables, run the following command: `iptables -t nat -D OUTPUT -p tcp -d 169.254.169.254 --dport 80 -j DNAT --to-destination 127.0.0.1:54321`

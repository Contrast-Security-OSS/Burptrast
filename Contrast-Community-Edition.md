
# Burptrast & Contrast Community Edition
Contrast has a Community Edition of Assess that can be used in conjunction with Burptrast. while this is limited to a Single application and supports only Java, .NET Core or Node applications. It gives you the ability to try out Burptrast for free.

## Signup
To setup go to https://www.contrastsecurity.com/contrast-community-edition and sign up at the bottom of the page.
A link will be sent to you to create a password ( This can take several minutes ).
PHOTO
PHOTO

Sign up

### Configure your application
You will need to add the Agent to the application you wish to instrument. Details of this are availble for [Java](https://docs.contrastsecurity.com/en/install-the-java-agent.html) and  [.NET Core](https://docs.contrastsecurity.com/en/install--net-core.html)
Or if you wish to trial this with PetClinic, follow these steps.

Login to https://ce.contrastsecurity.com . If this is the first login, select configure agent. If you reach the main dashboard click the Plus sign ( + ) at the top right of the page.
![Configure Agent 1](screenshots/configure-agent-1.png)
Select Java from the drop down and click "Download the Java contrast_security.yaml"
This file contains the details the agent needs to report results back to TeamServer. It should look like this

**contrast_security.yaml**
```
api:
url: https://ce.contrastsecurity.com/Contrast
api_key: XXXXXXXXX
service_key: XXXXXXXXX
user_name: agent_XXXXXXXXX
```
Download the agent jar file, there are a few ways, but there is a direct link to the contrast.jar file at the bottom of the page. Or you can the contrast.jar from maven https://mvnrepository.com/artifact/com.contrastsecurity/contrast-agent

Clone the petclinic application
```
git clone https://github.com/Contrast-Security-OSS/demo-petclinic.git
```
There are several ways to run the application, the petclinic readme gives the details. 
Assuming you have docker installed, the easiest way is to follow the Running in Docker part of the Petclinic readme

Copy the contrast_security.yaml file to the root of the petclinic project e.g
```
cp contrast_security.yaml demo-petclinic/
```
Build the docker image
```
cd demo-petclinic/
./1-Build-Docker-Image.sh
```


Run Petclinic

**Please Note, running the application will use up your single Application license.**
If you wish to instrument another application you would need to contact Contrast to get a license, or create another CE addition account.
```
docker run -v $PWD/contrast_security.yaml:/etc/contrast/java/contrast_security.yaml -p 8080:8080 spring-petclinic:1.5.1
```
Once started it should be available on [http://localhost:8080/]()

### Configuring Burptrast

Once you have the instrumented application running, Install Burptrast into Burp, see the README.md for details.
#### Login
Go to the credentials tab
![Credentials Tab](screenshots/cred-tab.png)

Select Teamserver URL https://ce.contrastsecurity.com/Contrast from the Dropdown
Enter your email and password and press login.
The Status should change from "Awaiting Credentials" to "Ready".
If you don't wish to login each time, you can save the credentials to disk.
This does not store your password, but instead stores the API and Service Key into a file. If you do this it is your responsibility to store this file securely.
Then when you need to connect again, you can select the Credentials file instead of logging in.

#### Use Burptrast
Under the Contrast tab from the Application Drop down select your application in this case "spring-petclinic" from the application name drop down.
Then select Update.



Burptrast will retrieve the list of known vulnerabilities, in the paid for version of Assess, you will also see a list of paths in the application. However on the Community Edition this is currently disabled.


Once done you can import those Routes into Burp's Sitemap and the vulnerabilities into Burp's Issue Tab ( If you are using Professional edition, the Issue Tab is disabled in Burp Community ).
Also select "Live Browsing". 
Once done you are ready to access the application via Burp's Proxy.
As you exercise the application via Burp's Proxy, using Burp itself or another tool or Browser, Assess will be running in the background


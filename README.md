# MMSGate
MMSGate is a MMS message gateway between VoIP.ms and Linphone clients.

Linphone is an open-source soft-phone.  It makes VoiP SIP calls and can send/receive SMS/MMS messages over the SIP protocol.  It can also use push notifications to ensure no calls are missed and SMS/MMS are delivered quickly.  

VoIP.ms provides voice and SMS over SIP protocol.  While MMS messages are possible, the service is provided over a customized API and web hook.  MMSGate provides the link between VoIP.ms's MMS service and Linphone clients.

The Linphone clients connect through Flexisip to VoIP.ms.  MMSgate uses PJSIP to communicate via SIP and web interfaces to communicate with VoIP.ms.  MMSGate intercepts MMS messages, inbound and outbound, and forwards them via the appropriate communications method.  

![mmsgate-2](https://github.com/RVgo4it/mmsgate/assets/112497289/8e35b19f-5511-4d55-9119-544b2ee2abea)

## Requirements and Prerequisites
It is strongly recommended to have the following equipment, resources, information and knowledge available before attempting this procedure.

* Ubuntu Server 22.04 LTS
	* Either a Raspberry Pi aarch64/arm64 or Intel/AMD x86_64/amd64
	* Recommend: Raspberry Pi 4 Model B with 4G or more memory.  
* DNS name that will point to the Flexisip/MMSGate server, i.e. flexisip.yourDomian.com
* One or more VoIP.ms DIDs and one or more sub accounts.
* For SIPS (TLS) transport and web HTTPS, the certificate chain and private key for the DNS name.
* Your VoIP.ms portal account ID and password.
* An API password and enabled API via https://voip.ms/m/api.php.
* Basic knowledge of Linux (Installing an OS, copying files, logon, logoff, others)
* Basic networking knowledge (firewall, NAT, IP address, ports, TCP, UDP)

## Prepare the Ubuntu Server

The Ubuntu server, often referred to as the host in this document, will act as the platform for MMSGate.  It is expected to be powered on and operational nearly all the time.  Logon as usual and arrive at a command prompt.  Update the host and set its name to match your DNS name, replacing "flexisip.yourDomian.com" as needed in these commands:
```
sudo apt update
sudo apt upgrade
sudo hostnamectl set-hostname flexisip.yourDomian.com
```
Shutdown and reboot the host as usual or use this command:
```
sudo shutdown -r now
```
Once logged back in, if Docker not already installed, do this:
```
sudo apt install docker.io
```
Then upgrade the builder:
```
sudo apt install docker-buildx
```
To make future activity easier, grant your user Docker rights:
```
sudo usermod -a -G docker $USER
```
logoff and back in again or use this command:
```
su -  $USER
```
## Build Docker Images
Docker Images hold the software needed to run the MMSgate system.

Create a location for the software and switch to it using these commands:
```
mkdir ~/mmsgate-system
cd ~/mmsgate-system
```
Get a copy of this repository:
```
git clone https://github.com/RVgo4it/mmsgate --recursive -b main
```
Build the first Docker image layer wih Flexisip:
```
docker build -t flexisip -f mmsgate/Dockerfile_flexisip_install --build-arg="BRANCH=release/2.3" .
```
Build a layer for PJSIP.
```
docker build -t pjsip -f mmsgate/Dockerfile_pjsip_install --build-arg="BRANCH=support-2.14.1" .
```
The build-args parameter in the last two commands can be altered to build different versions.  Be sure to use "docker system prune" to clear out the cache between versions.  

Finally, install MMSGate as the final layer.
```
docker build -t mmsgate -f mmsgate/Dockerfile_mmsgate_install .
```
To see the images, use this command:
```
docker image ls
```
Images are built in layers.  The MMSGate image may show a size of about 400Mb, but that is actually a total including all the lower layers.  

We can now create a container to run the software in the images.  We'll mount timezone configurations to the host so they will match. 
Keep in mind that Docker containers are transitory.  Thus, we need to put the configuration and data stored in a persistent volume.  We'll also directly use the host's network and call the container mmsgate by using this command:
```
docker run --name mmsgate -d --network host \
  -v /etc/timezone:/etc/timezone -v /etc/localtime:/etc/localtime \
  -v datavol:/home/mmsgate/data \
  -v confvol:/etc/flexisip \
  -v mmsmediavol:/home/mmsgate/mmsmedia mmsgate
```
The host's backup system should be configured to backup the volume data as part of its normal activity. Make sure it includes this path: /var/lib/docker/volumes.  To see a list of volumes, use this command:
```
docker volume ls
```
To see the startup logs, use this command:
```
docker logs mmsgate
```
To confirm the mmsgate container is running, use this command:
```
docker ps -a
```
Status should show "up".  If so, tell Docker to restart the container if it stops.  
```
docker update --restart unless-stopped mmsgate
```
Docker can consume significant disk space.  Use these commands to monitor and clean up space.
```
df -h
docker system prune
```
Once the builds are done, you can delete the downloaded files.
```
cd ~
rm -rf ~/mmsgate-system
```
## Flexisip Configuration
Configure Flexisip as a push gateway.  

Bind the interface to the local IP and use the host's DNS name.  For details on all the other required settings, follow this guide: https://wiki.linphone.org/xwiki/wiki/public/view/Flexisip/HOWTOs/Push%20Gateway/

To edit the Flexisip configuration, use this command:
```
docker exec -it mmsgate sudo nano /etc/flexisip/flexisip.conf
```
Use Ctrl-S to save and Ctrl-X to exit.  You can search the file using Ctrl-W.  

The "transports" line may look something like this:
```
transports=sips:flexisip.yourdomain.com;maddr=123.45.67.89
```
To view the Flexisip log file as it is appended to, use this command:
```
docker exec -it mmsgate tail -f /var/opt/belledonne-communications/log/flexisip/flexisip-proxy.log
```
See the Logs section of this document for more details.  

To start or stop the container, use these commands:
```
docker stop mmsgate
docker start mmsgate
```
Note: Try to avoid restarting Flexisip.  Restarting Flexisip will cause any current calls to drop, plus loss of current registrations and buffered messages, both kept in memory.  It may require some of the clients to re-register via opening the client app.  See the Flexisip Message Queue Database section of this document for details on the buffered message.  

To copy files into or out of the container, use commands like these:
```
docker cp mmsgate:/etc/flexisip/flexisip.conf /tmp/flexisip.conf.old
docker cp ~/Downloads/mmsgate-abcde-f0123456789a.json mmsgate:/etc/flexisip
```
Test voice calls and SMS messaging from your Linphone clients.  MMS messaging is not operational at this point.  SMS messaging should work, but only the sub account designated in the DID configuration at VoIP.ms will receive a copy of an incoming SMS message.  

Once Flexisip working as expected, move on to setup MMSGate.

* Tips:
	* For SIPS (TLS), the recommended transport, it's best to import the client config via "Fetch Remote Configuration" with the SIPS URI already defined in the XML.  Otherwise, client may still try to use SIP and fail.  Details in the XML Config section of this README. 
	* For Android clients to use push notification, you'll need a https://firebase.google.com project definition "google-services.json" and authentication keys similar to "MyMMSgateProj-fedcba-0123456789ac.json".  Details in the Android Push Notification section of this README.
	* The authentication keys are used in Flexisip server configuration and the project definition is used in compiling https://gitlab.linphone.org/BC/public/linphone-android.  
	* If Flexisip is behind a NAT firewall, use this guide: https://wiki.linphone.org/xwiki/wiki/public/view/Flexisip/HOWTOs/Deploying%20flexisip%20behind%20a%20NAT/
	* To help prevent unauthorized use of the proxy, you can enable Flexisip's garbage module and have it trash all unwanted traffic.
		* Edit the /etc/flexisip/flexisip.conf file.
		* Find the "[module::GarbageIn]" section.
		* Set "enabled=true"
		* Set filter to "filter= ! ( from.uri.user contains '123456_' || to.uri.user contains '123456_' )" replacing 123456 with your account prefix.  
	* To confirm the Linphone client is passing it's push notification settings in its contact URI, use commands like the following to confirm registration and look for "pn" parameters:
```
docker exec -it mmsgate sudo /opt/belledonne-communications/bin/flexisip_cli.py REGISTRAR_DUMP
docker exec -it mmsgate sudo /opt/belledonne-communications/bin/flexisip_cli.py REGISTRAR_GET sip:123456_bob@deluth2.voip.ms
```
## MMSGate configuration
These steps will configure MMSGate so it can communicate with VoIP.ms and Flexisip.  

If MMSGate is behind a firewall/NAT router, ensure the TCP web hook/media port, default of 38443, is allowed and/or forwarded.  

From host server, edit the Flexisip config file:
```
docker exec -it mmsgate sudo nano /etc/flexisip/flexisip.conf
```
We need Flexisip to be able to talk to MMSGate via local loopback IP.  In the "[global]" section, find option "transports" and add the following to the end, separated by a space from the existing transports:
```
sips:localhost;maddr=127.0.0.1;tls-verify-outgoing=0 sip:localhost;maddr=127.0.0.1
```
Also, need to define a forward rule for sending MMS messages over to MMSGate.  In the "[module::Forward]" section, enable it and add the following option:
```
routes-config-path=/etc/flexisip/forward.conf
```
Once back at the command prompt, edit the forward.conf file using this command:
```
docker exec -it mmsgate sudo nano /etc/flexisip/forward.conf
```
We need to send all SIP messages from the Linphone clients that are not text, that being MMS or other types that VoIP.ms can't process, over to the MMSGate.  Add a line as per the following:
```
<sip:127.0.0.2>     request.method == 'MESSAGE' && user-agent contains 'Linphone' && content-type != 'text/plain'
```
For internal extension support, we also need to send any messages send to an internal extension over to MMSGate.  Add a line as per the following:
```
<sip:127.0.0.2>     request.method == 'MESSAGE' && user-agent contains 'Linphone' && to.uri.user regex '10[0-9]{1,10}'
```
Once back at the command prompt, edit the MMSGate configuration file using this command:
```
docker exec -it mmsgate sudo nano /etc/flexisip/mmsgate.conf
```
Add API ID and password, "[api]" section, options "apiid" and "apipw", also in section "[web]", option "webdns" name.  Add other settings as needed.

Once back at the command prompt, restart the mmsgate container.  Move on to setup VoIP.ms.  

Tasks MMSGate does not do and should be addressed:
* MMS media is taged as expiring in one year.  However, MMSGate does not automatically remove media after that time.
* Records in the MMSGate database are not automatically removed.  See the MMSGate Database section of this document to address this.  

## Setup VoIP.ms
The following will configure your VoIP.ms account to work with MMSGate.

Logon to VoIP.ms portal, https://voip.ms/

* Select "DID Numbers"->"Manage DID(s)".
* Edit each DID that will be used with MMSGate.  
	* Enable "Message Service (SMS/MMS)"
	* Disable "Link the SMS received to this DID to a SIP Account"
	* Enable "SMS/MMS Webhook URL (3CX)" and set it to something like one of these, depending on your domain, port and protocol:
		* http://flexisip.yourDomian.com:38443/mmsgate
		* https://flexisip.yourDomian.com:38443/mmsgate
	* Enable "URL Callback and Webhook URL Retrying"
	* Edit other settings as needed.
	* Apply changes

* Select "Sub Accounts"->"Manage Sub Accounts".
* There is to be one sub account for each Linphone client.
* Edit each sub account that will be used with MMSGate.  
	* Edit "CallerID Number", selecting the DID that will be associated with sending and receiving SMS/MMS messages for this account.
	* Edit "Encrypted SIP Traffic", matching the clients transport method.
	* Edit other settings as needed.
	* Apply changes

Once done, test MMS and SMS messaging.  

## Android Push Notification

To use push notifications on Android via Flexisip, we need Firebase and Cloud Messaging.  Open the following URL:

https://firebase.google.com/

Sign in and go to the Console.

Create a project and call it "mmsgate".

Once at the project overview, add an Android app by clicking the Android icon.

If you opened project settings, you can also add an Android app from the General tab.

For the app's Package name, use your domain in reverse and end with linphone.  For example:
```
	com.yourdomain.linphone
```
After the app is registered, download the "google-services.json" file and keep it in a safe place.  It needs to be added to the Android app source project.

After returning to the project settings, select the Cloud Messaging tab.

Under Firebase Cloud Messaging API (V1), select Manage Service Accounts and the Cloud console will appear.

There should be a service account listed, to its right, there is an action menu.  Select Manage Keys.

Click ADD KEY and select Create new key.  Key type is JSON and click Create.  Download the file named similar to "mmsgate-abcde-f0123456789a.json" and keep it in a safe place.  It needs to be added to the Flexisip server configuration.

From an Ubuntu Desktop 22.04 LTS system (recommended), or most any Intel/AMD x86_64/amd64 system with Docker, open a command prompt.  The compilation process for an Android application will need significant memory, 8GB or more of memory is recommended.  

If Docker not already installed, do this:
```
sudo apt install docker.io
```
Upgrade the builder:
```
sudo apt install docker-buildx
```
Grant current user Docker rights:
```
sudo usermod -a -G docker $USER
```
logoff and back in again or use this command:
```
su -  $USER
```
Need a location for the software.  Create it and switch to it.  
```
mkdir ~/linphone-android-app
cd ~/linphone-android-app
mkdir ./empty
```
Download source for the Linphone SDK.  
```
git clone https://gitlab.linphone.org/BC/public/linphone-sdk.git --recursive -b release/5.3
```
Download the source for the Android application.
```
git clone https://gitlab.linphone.org/BC/public/linphone-android --recursive -b release/5.2
```
The "-b" parameter in the last two commands can be altered to build different versions.  

Copy the "google-services.json" files downloaded from firebase.google.com to "~/linphone-android-app/linphone-android/app/google-services.json", replacing the one there.

Use this command to see available docker files for Android builds:
```
ls -l linphone-sdk/docker-files/*andr*
```
Examine docker files listed and pick newest that is not for testing, for example "bc-dev-android-r25b".  Modify the next command to reflect the selected docker file and run:
```
docker build -f linphone-sdk/docker-files/bc-dev-android-r25b -t linphone-android ./empty
```
Next, create a container and open a command prompt inside the container.
```
docker run -it -v $PWD/linphone-sdk:/home/bc/linphone-sdk -v $PWD/linphone-android:/home/bc/linphone-android linphone-android /bin/bash -i
```
Once inside the container, build the SDK:
```
cd ~/linphone-sdk
cmake --preset=android-sdk -B build-android -DLINPHONESDK_ANDROID_ARCHS=arm64
cmake --build build-android --parallel 5
```
Before building the Android application, we must configure it:
```
cd ~/linphone-android
cat app/google-services.json
```
Note the package name, your DNS name in reverse.

Use the following command to edit the "PackageName" statement, about line 12, to match your package name.
```
nano app/build.gradle
```
It will look something like this:
```
	def packageName = "com.yourdomain.linphone"
```

Once back at command prompt, use the following command to edit "keystore.properties", enter a desired password in two places and the alias as "linphone-alias".
```
nano keystore.properties
```
Back at command prompt, use the following command to generate a new keystore.  Enter the same password you selected in the previous step.
```
keytool -genkey -v -keystore app/bc-android.keystore -alias linphone-alias -keyalg RSA -keysize 2048 -validity 3650 -dname "OU=None"
```
Compile the Linphone app.
```
./gradlew AssembleRelease
```
Once done, exit the container.
```
exit
```
Assuming no errors, there is now a .apk file in "~/linphone-android-app/linphone-android/app/build/outputs/apk/release".  Transfer the .apk file to your Android phone and install it.

Configure Flexisip as per:
https://wiki.linphone.org/xwiki/wiki/public/view/Flexisip/Configuration/Push%20notifications/

Once confirmed working, you can remove the ~/linphone-android-app folder.  You can clean up the Docker image, container and cache using these commands:
```
docker container prune
docker image rm linphone-android
docker system prune
```
## XML Configuration
The easiest way to configure a Linphone client is with an XML configuration file.  A script is available to make that easier.  It will also create QR code images so as to make finding the XML file from the Linphone client easier.

Logon to the MMSGate host server as usual.

If QR code generation is needed, install the Python qrcode library using this command:
```
docker exec -it mmsgate sudo apt install python3-qrcode
```
To create the XML config file or files, including passwords, use this command:
```
docker exec -it mmsgate sudo su -c "/home/mmsgate/script/makexmlconf.py" mmsgate
```
Note: It is recommended that once the client is configured, for security reasons, remove the XML config file from the container.

If no password is to be included in the XML file, causing the client to prompt for a password, use this command:
```
docker exec -it mmsgate sudo su -c "/home/mmsgate/script/makexmlconf.py --no-password" mmsgate
```
The following are all the command options available:
```
usage: makexmlconf.py [-h] [--no-password] [--add-path ADD_PATH] [--web-path WEB_PATH] [--local-path LOCAL_PATH]

options:
  -h, --help            show this help message and exit
  --no-password         Do not store the password in the XML config file.
  --add-path ADD_PATH   Add this path to the local and web paths. Default is "conf".
  --web-path WEB_PATH   Use this URL path for the locations. Default is the settings in mmsgate.conf.
  --local-path LOCAL_PATH
                        Use this local path for the file locations. Default is the setting in mmsgate.conf.
```
The script will display the URL needed by the client.  Optionally, it will also display the container path to QR code image file.  Send the end user the URL and/or the QR code image.

From the Linphone client, select "Assistant" and "Fetch remote configuration".  Enter the URL to the XML file or scan the QR code.  Then tap "Fetch and apply" and the Linphone app configuration is complete.

However, other settings will be needed to insure Linphone can respond and connect to the network when needed.  Mobile operating system will often put apps to sleep and cut them off from network data.  Adjust the settings as needed to allow the Linphone app to wake up and access network data to respond to push notifications or to renew it's registration.  Test the settings while on Wifi and on mobile data.  To monitor registration renewals so as to confirm proper operations, use this command:
```
docker exec -it mmsgate sudo su -c /home/mmsgate/script/regmon.py mmsgate
```

## Flexisip Message Queue Database
Normally, when a Flexisip receives a message for a Linphone client from MMSGate, it wakes up the client via Push Notification and delivers it immediately.  However, sometimes the client is unresponsive. In this case, Flexisip buffers the message in memory until the client is available.  

If Flexisip were to be restarted, these buffered messages in memory would be lost.  To prevent this, use this procedure to create a database for the messages.

From the host, use this command to install MariaDB server inside the container:
```
docker exec -it mmsgate sudo apt install mariadb-server
```
Restart the mmsgate container.  Once restarted, open a MariaDB client prompt using this command:
```
docker exec -it mmsgate sudo mysql
```
Use the following commands to create the database and user for Flexisip messages:
```
CREATE DATABASE flexisip_msgs;
CREATE USER 'flexisip'@localhost IDENTIFIED BY 'password1';
GRANT ALL PRIVILEGES ON *.* TO 'flexisip'@localhost;
FLUSH PRIVILEGES;
exit
```
Edit the flexisip.conf file, find the "[module::Router]" section and edit/add the following options:
```
message-database-enabled=true
message-database-backend=mysql
message-database-connection-string=db='flexisip_msgs' user='flexisip' password='password1' host='localhost'
```
Restart the mmsgate container.  

## MMSGate Database
MMSGate uses a SQLite3 database with a single table.  All messages received by MMSGate, inbound or outbound, are stored in this database.

To view the database, and for other database actions, you’ll need to install the SQLite3 command line tools into the container.  Use the following command on the host to install them:
```
docker exec -it mmsgate sudo apt install sqlite3
```
Then, assuming the default database location, use this command to display the table:
```
docker exec mmsgate sudo su -c "sqlite3 -box ~/data/mmsgate.sqlite \" \
  SELECT rowid,msgid,strftime('%Y-%m-%d %H:%M',datetime(rcvd_ts, 'unixepoch', 'localtime')) as rcvd_ts, \
    strftime('%Y-%m-%d %H:%M',datetime(sent_ts, 'unixepoch', 'localtime')) as sent_ts,fromid,fromdom,toid, \
    todom,substr(message,1,15) as message,direction as dir,msgstatus as msgstat,did,msgtype,trycnt FROM send_msgs; \
  \"" mmsgate
```
The database may grow to an excessive size.  To delete messages received over 30 days ago, use this command:
```
docker exec mmsgate sudo su -c "sqlite3 ~/data/mmsgate.sqlite \" \
  DELETE FROM send_msgs WHERE rcvd_ts < CAST(strftime('%s',date('now','-30 days')) AS INTEGER); \
  \"" mmsgate
```
Then compact the database using this command:
```
docker exec mmsgate sudo su -c "sqlite3 ~/data/mmsgate.sqlite \"VACUUM;\"" mmsgate
```
However, the vacuum command can change the row IDs of a SQLite table.  MMSGate depends on the row ID.  Thus, when automating the vacuum command, precede it with this command to stop MMSGate for 60 seconds:
```
docker exec mmsgate bash -c "sudo kill \$(pgrep mmsgate.py)"
```
To compare the database contents with the message history from VoIP.ms, and reconcile any missing messages, use this command:
```
docker exec mmsgate sudo su - -c "/home/mmsgate/script/mmsreconcile.py" mmsgate
```
It will look back 7 days as a default.  The --look-back option can be used to adjust the number of days.  

The reconcile and delete commands can be placed in a bash script and scheduled via crontab to run nightly on the host.  The kill and vacuum commands can be weekly.  

## Logs
To see more detailed logs for Flexisip, you can increase the details without having to restart Flexisip.  

From the host’s command prompt, confirm the current log level with this command:
```
docker exec -it mmsgate sudo /opt/belledonne-communications/bin/flexisip_cli.py CONFIG_GET global/log-level
```
Use the following command to increase the log level:
```
docker exec -it mmsgate sudo /opt/belledonne-communications/bin/flexisip_cli.py CONFIG_SET global/log-level debug
```
Then view the log via this command:
```
docker exec -it mmsgate tail -f /var/opt/belledonne-communications/log/flexisip/flexisip-proxy.log
```
Use the following command to reset the log level back to default:
```
docker exec -it mmsgate sudo /opt/belledonne-communications/bin/flexisip_cli.py CONFIG_SET global/log-level error
```
To modify the PJSIP or MMSGate log levels, the MMSGate configuration needs to be modified.  Use this command:
```
docker exec -it mmsgate sudo nano /etc/flexisip/mmsgate.conf
```
For PJSIP logs, in the "[sip]" section, set option "siploglevel" to level "5" for the highest.  Also set "siplogfile" to "/tmp/sip.log".  

Once back at a command prompt, restart the MMSGate script using this command:
```
docker exec -it mmsgate bash -c "sudo kill \$(pgrep mmsgate.py)"
```
Wait 60 seconds.  To view the log as it is appended to, use this command:
```
docker exec -it mmsgate tail -f /tmp/sip.log
```
Note: PJSIP does not flush the log buffers very often.  So, appended log entries will appear in chunks.  

To modify the MMSGate log level details, again edit the "mmsgate.conf" file.  In the "[mmsgate]" section, set option "logger" to "DEBUG".  Also set "loggerfile" to "/tmp/mmsgate.log".  Again, restart MMSGate script and wait 60 seconds.  Then use this command to view the log file:
```
docker exec -it mmsgate tail -f /tmp/mmsgate.log
```
Once done, return the settings in the MMSGate configuration file to their original values and restart the MMSGate script.  

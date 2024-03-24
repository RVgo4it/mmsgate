# MMSGate
MMSGate is a MMS message gateway between VoIP.ms and Linphone clients.

Linphone is an open-source soft-phone.  It makes VoiP SIP calls and can send/receive SMS/MMS messages over the SIP protocol.  For voice calls, it can also use push notifications to ensure no calls are missed.  

VoIP.ms provides voice and SMS over SIP protocol.  While MMS messages are possible, the service is provided over a customized API and web hook.  MMSGate provides the link between VoIP.ms's MMS service and Linphone clients.

The Linphone clients connect through Flexisip to VoIP.ms.  MMSgate uses PJSIP to communicate via SIP and web interfaces to communicate with VoIP.ms.  MMSGate intercepts MMS messages, inbound and outbound, and forwards them via the appropriate communications method.  

![mmsgate-2](https://github.com/RVgo4it/mmsgate/assets/112497289/8e35b19f-5511-4d55-9119-544b2ee2abea)

## Requirements and Prerequisites
It is strongly recommended to have the following equipment, resources, information and knowledge available before attempting this procedure.

* Ubuntu Server 22.04 LTS
	* Either a Raspberry Pi aarch64/arm64 or Intel/AMD x86_64/amd64
	* Recommend: Raspberry Pi 4 Model B with 2G or more memory.  
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
Shutdown and reboot the host as usual or using this command:
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

We can now create a container to run the software in the images.  Keep in mind that Docker containers are transitory.  Thus, we need to create a container with the configuration and data stored in a persistent volume using this command:
```
docker run --name mmsgate -d --network host -v datavol:/home/mmsgate/data -v confvol:/etc/flexisip -v mmsmediavol:/home/mmsgate/mmsmedia mmsgate 
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
Configure Flexisip as a push gateway.  Bind the interface to the local IP and use the host's DNS name.  
ref: https://wiki.linphone.org/xwiki/wiki/public/view/Flexisip/HOWTOs/Push%20Gateway/

To edit the Flexisip configuration, use this command:
```
docker exec -it mmsgate sudo nano /etc/flexisip/flexisip.conf
```
The transport line may look something like this:
```
transports=sips:flexisip.yourdomain.com;maddr=123.45.67.89
```
To view the Flexisip log file as it is appended to, use this command:
```
docker exec -it mmsgate tail -f /var/opt/belledonne-communications/log/flexisip/flexisip-proxy.log
```
To start or stop the container, use these commands:
```
docker stop mmsgate
docker start mmsgate
```
Docker can consume significant disk space.  Use these commands to monitor and clean up space.
```
df -h
docker system prune
```
To copy files into or out of the container, use commands like these:
```
docker cp mmsgate:/etc/flexisip/flexisip.conf /tmp/flexisip.conf.old
docker cp ~/Downloads/mmsgate-abcde-f0123456789a.json mmsgate:/etc/flexisip
```
Test voice calls and SMS messaging from your Linphone clients.  MMS messaging is not operational at this point.  SMS messaging should work, but only the sub account designated in the DID configuration at VoIP.ms will receive a copy of an incoming SMS message.  

Once the builds are done, you can delete the downloaded files.
```
rm -r ~/mmsgate-system
```
Once Flexisip working as expected, move on to setup MMSGate.

* Tips:
	* For SIPS (TLS), the recommended transport, it's best to import the client config via "Fetch Remote Configuration" with the SIPS URI already defined in the XML.  Otherwise, client may still try to use SIP and fail.  
	* For Android clients to use push notification, you'll need a https://firebase.google.com project definition "google-services.json" and authentication keys similar to "MyMMSgateProj-fedcba-0123456789ac.json".  Details in the Android Push Notification section of this README.
	* The authentication keys are used in Flexisip server configuration and the project definition is used in compiling https://gitlab.linphone.org/BC/public/linphone-android.  
	* If Flexisip is behind a NAT firewall, use this guide: https://wiki.linphone.org/xwiki/wiki/public/view/Flexisip/HOWTOs/Deploying%20flexisip%20behind%20a%20NAT/
	* To confirm the Linphone client is passing it's push notification settings in its contact URI, use a command like the following and look for "pn" parameters:
```
docker exec -it mmsgate sudo /opt/belledonne-communications/bin/flexisip_cli.py REGISTRAR_GET sip:123456_bob@deluth2.voip.ms
```
## MMSGate configuration
These steps will configure MMSGate so it can communicate with VoIP.ms and Flexisip.  

If MMSGate is behind a firewall/NAT router, ensure the TCP web hook/media port, default of 38443, is allowed and/or forwarded.  

From host server, edit the Flexisip config file:
```
docker exec -it mmsgate sudo nano /etc/flexisip/flexisip.conf
```
We need Flexisip to be able to talk to MMSGate via local loopback IP.  In the [global] section, find option transports and add the following to the end, separated by a space from the existing transports:
```
sips:localhost;maddr=127.0.0.1;tls-verify-outgoing=0 sip:localhost;maddr=127.0.0.1
```
Also, need to define a forward rule for sending MMS messages over to MMSGate.  In the [module::Forward] section, add option as follows:
```
routes-config-path=/etc/flexisip/forward.conf
```
Once back at the command prompt, edit the forward.conf file using this command:
```
docker exec -it sudo nano /etc/flexisip/forward.conf
```
We need to send all SIP messages from the Linphone clients that are not text, that being MMS or other types that VoIP.ms can't process, over to the MMSGate.  Add a line as per the following:
```
<sip:127.0.0.2>     request.method == 'MESSAGE' && user-agent contains 'Linphone' && content-type != 'text/plain'
```
Once back at the command prompt, edit the MMSGate configuration file using this command:
```
docker exec -it sudo nano /etc/flexisip/mmsgate.conf
```
Edit the MMSGate config, adding API ID and password, webdns name and other settings as needed.  

Once back at the command prompt, restart the mmsgate container.

## Setup VoIP.ms

The following will configure your VoIP.ms account to work with MMSGate.

Logon to VoIP.ms portal, https://voip.ms/

* Select "DID Numbers"->"Manage DID(s)".
* Edit each DID that will be used with MMSGate.  
	* Enable "Message Service (SMS/MMS)"
	* Disable "Link the SMS received to this DID to a SIP Account"
	* Enable "SMS/MMS Webhook URL (3CX)" and site it to something like these, depending on your domain, port and protocol:
		* http://flexisip.yourDomian.com:38443/mmsgate
		* https://flexisip.yourDomian.com:38443/mmsgate
	* Enable "URL Callback and Webhook URL Retrying"
	* Edit other settings as needed.
	* Apply changes

* Select "Sub Accounts"->"Manage Sub Accounts".
* Edit each sub account that will be used with MMSGate.  
	* Edit "CallerID Number", selecting the DID that will be associated with sending and receiving SMS/MMS messages for this account.
	* Edit "Encrypted SIP Traffic", matching the clients transport method.
	* Edit other settings as needed.
	* Apply changes

Once done, test the MMS and SMS messaging.  

## Android Push Notification

To use push notifications on Android via Flexisip, we need Firebase and Cloud Messaging.  Open the following URL:

https://firebase.google.com/

Sign in and go to the Console.

Create a project and call it mmsgate.

Once at the project overview, add an Android app by clicking the Android icon.

If you opened project settings, you can also add an Android app from the General tab.

For the app's Package name, use your domain in reverse and end with linphone.  For example:
```
	com.yourdomain.linphone
```
After the app is registered, download the google-services.json file and keep it in a safe place.  It needs to be added to the Android app source project.

After returning to the project settings, select the Cloud Messaging tab.

Under Firebase Cloud Messaging API (V1), select Manage Service Accounts and the Cloud console will appear.

There should be a service account listed, to its right, there is an action menu.  Select Manage Keys.

Click ADD KEY and select Create new key.  Key type is JSON and click Create.  Download the file named similar to "mmsgate-abcde-f0123456789a.json" and keep it in a safe place.  It needs to be added to the Flexisip server.

From an Ubuntu 22.04 LTS Desktop system, but NOT the MMSGate server, open a command prompt.

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

Copy the google-services.json files downloaded from firebase.google.com to ~/linphone-android-app/linphone-android/app/google-services.json, replacing the one there.

Use this command to see available docker files for Android builds:
```
ls -l linphone-sdk/docker-files/*andr*
```
Examine docker files listed and pick newest that is not for testing, for example bc-dev-android-r25b.  Modify the next command to reflect the selected docker file and run:
```
docker build -f linphone-sdk/docker-files/bc-dev-android-r25b -t linphone-android .
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

Once back at command prompt, use the following command to edit keystore.properties, enter a desired password in two places and the alias as linphone-alias.
```
nano keystore.properties
```
Back at command prompt, use the following command to generate a new keystore.  Enter the same password you selected in the previous step.
```
keytool -genkey -v -keystore app/bc-android.keystore -alias linphone-alias -keyalg RSA -keysize 2048 -validity 3650 -dname "OU=None"
```
Compile the Linphone app
```
./gradlew AssembleRelease
```
Once done, exit the container.
```
exit
```
Assuming no errors, there is now a .apk file in ~/linphone-android-app/linphone-android/app/build/outputs/apk/release.  Transfer the .apk file to your Android phone and install it.

Configure Flexisip as per:
https://wiki.linphone.org/xwiki/wiki/public/view/Flexisip/Configuration/Push%20notifications/

Once confirmed working, you can remove the ~/linphone-android-app folder.  You can clean up the Docker image, container and cache using these commands:
```
docker container prune
docker image rm linphone-android
docker system prune
```

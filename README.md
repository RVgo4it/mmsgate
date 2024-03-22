# MMSGate
MMSGate is a MMS message gateway between Voip.ms and Linphone clients.

Linphone is an open-source soft-phone.  It makes VoiP SIP calls and can send/receive SMS/MMS messages over the SIP protocol.  For voice calls, it can also use push notifications to ensure no calls are missed.  

Voip.ms provides voice and SMS over SIP protocol.  While MMS messages are possible, the service is provided over a customized API and web hook.  MMSGate provides the link between Voip.ms's MMS service and Linphone clients.

The Linphone clients connect through Flexisip to Voip.ms.  MMSgate uses PJSIP to communicate via SIP and web interfaces to communicate with Voip.ms.  MMSGate intercepts MMS messages, inbound and outbound, and forwards them via the appropriate communications method.  

![mmsgate-2](https://github.com/RVgo4it/mmsgate/assets/112497289/8e35b19f-5511-4d55-9119-544b2ee2abea)

# Requirements and Prerequisites

	* Ubuntu Server 22.04 LTS
		* Either a Raspberry Pi aarch64/arm64 or Intel/AMD x86_64/amd64
		* Recommend: Raspberry Pi 4 Model B with 2G or more memory.  
	* DNS name that will point to the Flexisip/MMSGate server, i.e. flexisip.yourDomian.com
	* One or more Voip.ms DIDs and one or more sub accounts.
	* For SIPS (TLS) transport and web HTTPS, the certificate chain and private key for the DNS name.
	* Your Voip.ms portal account ID and password.
	* An API password and enabled API via https://voip.ms/m/api.php.
	* Basic knowledge of Linux (Installing an OS, copying files, logon, logoff, others)
 	* Basic networking knowledge (firewall, NAT, IP address, ports, TCP, UDP)

# Prepare the Ubuntu Server

The Ubuntu server, often referred to as the host in this document, will act as the platform for MMSGate.  It is expected to be powered on and operational nearly all the time.  Logon as usual and arrive at a command prompt.  Update the host and set it's name to match your DNS name, replacing "flexisip.yourDomian.com" as needed in these commands:
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
The host's backup system should be configured to backup the volume data as part of it's normal activity. Make sure it includes this path: /var/lib/docker/volumes.  To see a list of volumes, use this command:
```
docker volume ls
```
To see the startup Logs, use this command:
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
Test voice calls and SMS messaging from your Linphone clients.  MMS messaging is not operational at this point.  Once working as expected, move on to setup MMSGate.

* Tips:
	* For SIPS (TLS), the recommended transport, it's best to import the client config via "Fetch Remote Configuration" with the SIPS URI already defined in the XML.  Otherwise, client may still try to use SIP and fail.  
	* For Android clients to use push notification, you'll need a https://firebase.google.com project definition "google-services.json" and authentication keys similar to "MyMMSgateProj-fedcba-0123456789ac.json".  Details in the Android Push Notification section of this README.
	* The authentication keys are used in Flexisip server configuration and the project definition is used in compiling https://gitlab.linphone.org/BC/public/linphone-android.  
	* If Flexisip is behind a NAT firewall, use this guide: https://wiki.linphone.org/xwiki/wiki/public/view/Flexisip/HOWTOs/Deploying%20flexisip%20behind%20a%20NAT/
	* To confirm the Linphone client is passing it's push notification settings in its contact URI, use a command like the following and look for "pn" parameters:
```
docker exec -it mmsgate sudo /opt/belledonne-communications/bin/flexisip_cli.py REGISTRAR_GET sip:123456_bob@deluth2.voip.ms
```

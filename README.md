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

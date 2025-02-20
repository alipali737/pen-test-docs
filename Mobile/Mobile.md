
Routing network traffic is harder on mobile as each app is sandboxed. 

You need to jailbreak (root) a device to be able to interact and route the traffic etc.
But many apps check and stop working on rooted devices, so you need to bypass root detection.

IOS:
- Sideloadly - tool to sign an IPA (exploit like dopamine) and loading an exploit onto a phone

- Semi-teathered jailbreak : Doesn't persist the jail break after restart (can be easily re-jailbroke)
- Full jailbreak : Does persist upon restart

- Sileo app : like an app store for jailbroken phones to install packages
	- Allows you to SSH to phone
		- All apps get installed to `/var/containers/Bundle/Application/<UUID>`
		- Can get UUID using `find`
	- Frida package & cli tool - can use to list apps and get the UID 

- An app:
	- `info.plist` - information about what the app contains (incl permissions, maybe sensitive information can be found in there)
	- Normally built with Swift and Apple native frameworks

- SSL Pinning - Defence against packet interception
	- They have pinned the fingerprint of their public key in their TLS
	- So it rejects the connection as Burp sends its own certificate instead
	- `objection` - a tool build upon `frida` that 
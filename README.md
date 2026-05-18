<p align="center">
  <b>English</b> |
  <a href="README_RU.md">Русский</a>
</p>

# Happwner

Android app and Xposed module for decrypting links and exporting subscriptions from the proxy utility [Happ](https://play.google.com/store/apps/details?id=com.happproxy) to any VPN apps (NekoBox, v2rayNG, Hiddify, and similar clients).

## Why?

To give users control over their subscriptions again, improve service transparency, and protect themselves from dishonest resellers.

**Happ** is not just a VPN client, but part of a commercial ecosystem aimed at VPN providers. Happ gives them extended capabilities by introducing restrictions for users.

* Encrypted links (`happ://crypt5`) hide the real URL and prevent viewing server configurations;
* The hardware identifier (**HWID**) tightly binds a subscription to a specific device;
* The lack of advanced settings in Happ makes it impossible to hide traffic from questionable providers using proxy chains;
* If a [ProviderID](https://www.happ.su/main/dev-docs/provider-id) is embedded into a `crypt5` link, the application will once a day compare the subscription domain hash, app version, and OS version against the data specified in the seller’s dashboard on [happ-proxy.com](https://happ-proxy.com);
* A seller who added a **ProviderID** to an encrypted link gains the ability to remotely [control app](https://www.happ.su/main/dev-docs/app-management) without user interaction. Happ allows them to:
  * Force-enable HWID sending even if it is disabled in settings
  * Block manual User-Agent changing while allowing it to be modified remotely
  * Manage local SOCKS and HTTP proxies: reconfigure authentication or disable it
  * Automatically connect the user to a specific server when launching Happ
  * Disable global routing in Happ
  * Configure app proxying (add/remove exclusions)
  * Hide VPN servers depending on the connection type (Wi-Fi / mobile network)
  * Configure automatic server testing (auto-ping) when opening the application
  * Control the ping type (`via Proxy - GET/HEAD`, `TCP`, `ICMP`) and set a custom server testing URL
  * Change the subscription URL
  * Set the subscription auto-update interval
  * Enable Happ auto-start on device boot
  * Force-update all subscriptions every time the app starts
  * Expand the server list when a subscription is updated, or disable the list collapse completely
  * Pin or unpin subscriptions in the main list
  * Change server sorting order by alphabet or ping
  * Control traffic multiplexing (Mux)

**The list is incomplete.** Management parameters are sent through HTTP headers and the response body with each subscription update.

## Features

**Happwner** extracts clean VPN configurations and passes them into any applications.

Features:
* **One-click decryption of `crypt5` links** powered by the decryptor from **amurkanov**. All link versions are supported (from `crypt`, `crypt2`, etc. up to `crypt5`). Decryption does **not require** Happ, Xposed, LSPatch, or an internet connection.
* **HWID spoofing** when requesting a Happ subscription. Allows you to bypass the device limit and restore access to your subscription when switching devices;
* **Happ subscription update service** inside any apps (NekoBox, Hiddify, v2rayNG, husi, Exclave, Karing, etc.).

Features requiring **Xposed or LSPatch**:
* Interception of decrypted `crypt` links. This is an alternative decryption method and provides no advantages over the main method;
* HWID spoofing <u>inside Happ</u> and other target apps;
* Opening the interface with a three-finger tap gesture inside Happ or other target apps.

## Installation

### Without Xposed

1. Install the Happwner APK from [Releases](https://github.com/Omegaplexx/Happwner/releases).

The app supports **Android 5.0+ (Lollipop)**.

### Xposed

#### Root

1. Install Happwner and Happ;
2. Enable Happwner in your Xposed manager and select the recommended applications;
3. Restart Happ.

#### Without Root (LSPatch)

1. Install Happwner, Happ, [LSPatch](https://github.com/JingMatrix/LSPatch/releases) and [Shizuku](https://play.google.com/store/apps/details?id=moe.shizuku.privileged.api) (or [Split APKs Installer](https://f-droid.org/packages/com.aefyr.sai.fdroid) instead of Shizuku);
2. In the LSPatch manager, select **Happ** and choose a patch mode:
    * **Local**: patch and install the modified Happ, then select Happwner as the scope;
    * **Integrated**: embed the Happwner module, patch Happ, and install it.

##### Installing the patched APK

* **If the Shizuku service is running**, you can do this directly from the LSPatch manager;
* **If Shizuku is unavailable**, open Split APKs Installer (SAI), navigate to the *Download* folder, select all files containing `lspatched` in their names, and start the installation. <u>You may need to uninstall the original Happ first</u>.

**The modified Happ will launch successfully on the second attempt!** \
**LSPatch only supports Android 9 and above!**

## Acknowledgements

Special thanks to [amurkanov](https://github.com/amurcanov) for the [Happ Decrypt RS](https://github.com/amurcanov/happ-decrypt-universal) project. Happwner uses it as the primary method for link decryption.

## Disclaimer

I assume no obligations toward you as a user, do not guarantee the software will function correctly, and am not responsible for any actions you take.

This application may be used for malicious purposes, such as leaking private VPN servers publicly or reselling them. I condemn such activities. Use this tool responsibly: for personal convenience, or to share configurations with friends and family — but do not create problems for VPN providers, otherwise you may get banned, and I will have to adapt the project to their new ridiculous restrictions.
<p align="center">
  <b>English</b> |
  <a href="README_RU.md">Русский</a>
</p>

# Happwner

Android app and Xposed module for decrypting and exporting subscriptions from the proxy utility [Happ](https://play.google.com/store/apps/details?id=com.happproxy&utm_source=chatgpt.com) to any VPN applications (NekoBox, v2rayNG, Hiddify, and other).

## Why?

To give users control over their subscriptions again, improve service transparency, and protect themselves from dishonest resellers.

**Happ** is not just a VPN client, but part of a commercial ecosystem aimed primarily at VPN providers. It gives them extended capabilities by introducing restrictions for users.

* Encrypted links (`happ://crypt5`) hide the real subscription URL and prevent viewing configurations;
* The hardware identifier (**HWID**) tightly binds a subscription to a specific device;
* The lack of advanced settings in Happ makes it impossible to hide traffic from questionable providers using proxy chains;
* Once a day, Happ sends the subscription domain hash, app version, and OS version to the provider’s dashboard on [happ-proxy.com](https://happ-proxy.com) if the provider embedded a **ProviderID** into their `crypt5` link;
* A seller who added a **ProviderID** to the link can remotely control the application without user interaction using the following commands:
  * `import-data` — sends a subscription or server configuration;
  * `update-subscription` — updates all subscriptions on the device;
  * `set-settings` — reconfigures the application (fragmentation, MUX, local DNS, exclusions, auto-connect, Happ auto-start, ping type);
  * `sub-change` — changes the subscription domain.

## Features

**Happwner** extracts clean VPN configurations while bypassing artificial restrictions.

The application:
* Intercepts the **real** subscription links if they are encrypted (`crypt`, `crypt2`, `crypt3`, `crypt4`, `crypt5`). Enable link interception, launch Happ, and import/update the encrypted subscription. The real (decrypted) links will appear in the Happwner interface. **This feature requires Xposed/LSPatch!**
* Spoofs and persists the HWID inside Happ to bypass device limits or restore access after changing devices. **Requires Xposed/LSPatch!**
* Can run a local service that allows third-party apps (NekoBox, v2rayNG, etc.) to update Happ subscriptions without leaving their interface;
* Fully supports operation without Root or Xposed by embedding the module directly into the APK using the LSPatch method;
* Supports opening the interface with a three-finger tap gesture inside Happ;
* Supports all Android versions compatible with Happ — **Android 5.0+ (Lollipop)**.

## Installation

### Root (Xposed)

1. Install Happwner;
2. Enable the module in your Xposed manager (EdXposed/LSPosed/Vector);
3. Select **Happ** (`com.happproxy` and/or `su.happ.proxyutility`) as the target app;
4. Restart Happ.

### Without Root (LSPatch)

1. Install Happwner, [LSPatch](https://github.com/JingMatrix/LSPatch/releases), and [Shizuku](https://play.google.com/store/apps/details?id=moe.shizuku.privileged.api) (or [Split APKs Installer](https://f-droid.org/packages/com.aefyr.sai.fdroid) instead of Shizuku);
2. In the LSPatch manager, select **Happ** and choose a patch mode:
   * If you selected **Local**: patch and install the modified Happ, then select Happwner as the scope;
   * If you selected **Integrated**: embed the Happwner module, patch Happ, and install it.

#### Installing the patched APK

* **If the Shizuku service is running**, you can do this directly from the LSPatch manager;
* **If Shizuku is unavailable**, open Split APKs Installer (SAI), navigate to the *Download* folder, select all files containing `lspatched` in their names, and start the installation. <u>You may need to uninstall the original Happ first</u>.

**The modified Happ will launch successfully on the second attempt!**

## Disclaimer

I assume no obligations toward you as a user, do not guarantee the software will function correctly, and am not responsible for any actions you take.

This application may be used for malicious purposes, such as leaking private VPN servers publicly or reselling them. I condemn such activities. Use this tool responsibly: for personal convenience, or to share configurations with friends and family — but do not create problems for VPN providers, otherwise you may get banned, and I will have to adapt the project to their new ridiculous restrictions.

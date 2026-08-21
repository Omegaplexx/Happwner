<p align="center">
  <b>English</b> |
  <a href="README_RU.md">Русский</a>
</p>

# Happwner

<div align="center">
<img width="100" height="100" alt="Happwner icon" src="https://github.com/user-attachments/assets/93bc69a7-82b3-44b3-a577-52d6b56edc51" /><br><br>

An Android app for exporting encrypted subscriptions from the proxy utilities [Happ](https://play.google.com/store/apps/details?id=com.happproxy), [v2RayTun](https://play.google.com/store/apps/details?id=com.v2raytun.android) and [INCY](https://play.google.com/store/apps/details?id=llc.itdev.incy) into any VPN apps (NekoBox, v2rayNG, Hiddify, and similar clients).

<details>
<summary>Show screenshots</summary>
<div>
<img src="https://github.com/user-attachments/assets/11e8ce9d-02d6-4c9f-943d-d94277290ab8" width="30%" />
<img src="https://github.com/user-attachments/assets/b91e0269-4175-4111-b439-9972d13a0529" width="30%" />
<img src="https://github.com/user-attachments/assets/8c71d7e2-112b-445f-b1e5-53c30eaa7a74" width="30%" />
<img src="https://github.com/user-attachments/assets/f339409c-5505-49a3-9a2c-b7aa8a2837fe" width="30%" />
<img src="https://github.com/user-attachments/assets/c37acc91-86d3-401b-abd4-eba543a424a3" width="30%" />
<img src="https://github.com/user-attachments/assets/4d943fcf-a480-4396-9eb6-81b1235ae779" width="30%" />
<img src="https://github.com/user-attachments/assets/3293a5a3-aa3e-4d57-a719-ce6cdb1ce4f8" width="30%" />
</div>
</details>
</div>

<div align="center">

**Happwner** | [Happwner PC](https://github.com/Kasumicic/Happwner_PC) | [hpwnr](https://github.com/Omegaplexx/hpwnr)

</div>

## Quick start

1. Install the Happwner APK from [Releases](https://github.com/Omegaplexx/Happwner/releases) — Android 5.0 and above is supported;
2. Paste a `crypt` link into the URL field on the main screen and tap the key icon;
3. Enter any HWID, pick one of the built-in User-Agents and tap "Profiles" — the app will show configurations ready to be moved into your VPN client.

## Features

**Happwner** extracts clean VPN configurations and transfers them into any application. You do <u>not</u> need to install Happ to use all of its subscriptions.

* **Link decryption**. Supported formats:
  * **Happ**: `crypt`, `crypt2`, `crypt3`, `crypt4`, `crypt5` (old/new)
  * **v2RayTun**: `crypt3`, `crypt4`, `key3`
  * **INCY**: `crypt1`

  No internet connection required;

* **Subscription profile decryption**. If a provider encrypted their configs using one of the ten `key[01-10]` keys built into Happ, the app will automatically decrypt them and display the corresponding message;
* **HWID spoofing** when requesting subscriptions through the Happwner interface. Allows bypassing device limits and restoring access to subscriptions after changing devices;
* **Profile conversion** for better compatibility with VPN clients. See the [section below](#profile-conversion);
* **Subscription Bridge** — a service for updating Happ subscriptions inside any apps (NekoBox, Hiddify, v2rayNG, husi, Exclave, Karing, and others);
* **Intent link interception** for `happ://add` and its v2RayTun and INCY counterparts, so that subscription links go from the browser straight into Happwner;

## Profile conversion

Happ providers serve profiles as Xray JSON, which not every client understands. Happwner can "translate" those configs into one of three formats:

| Mode | Result | For which clients |
| --- | --- | --- |
| **Xray to URI** | `vless://`, `hy2://`, `trojan://` and other links | works with almost anything |
| **Xray to sing-box** | sing-box JSON configs | NekoBox, husi, Hiddify, Karing, and others |
| **Xray to Mihomo** | Mihomo (Clash Meta) YAML configs | FlClash, Clash Meta, Prizrak-Box, and others |

The mode is chosen separately for two cases:
* **Profiles** — for requesting configurations inside Happwner itself;
* **Subscription** — when another app requests them through the Bridge.

Not every profile converts without losses: some Xray features have no equivalents in other formats. Unsupported profiles are skipped, and their number is shown next to the result. The full list of limitations is in the app itself, in the description of each mode.

## Alternative decryption methods

These methods are for the rare cases where Happwner cannot decrypt a link on its own. All of them require extra steps on your side and do not guarantee a result.

### [Happanion](https://github.com/Omegaplexx/Happanion)

A companion app that installs **instead of** Happ from Google Play. It can decrypt `happ://crypt5` using the library from Happ and **force** browser intent links into Happwner. Installed from the Happwner settings, under "Decryption".

### Xposed

* **Link interception**. Works beyond Happ. Useful if the target app encrypts or hides the link it fetches profiles from;
* **HWID spoofing inside apps** marked as targets in the Xposed manager;
* **Access to `crypt` subscription profiles**. Happ and v2RayTun only. Forces profile parameters to be shown and allows exporting configs even when the subscription is encrypted;
* **Quick access to the Happwner interface** via a three-finger tap while a target app is open.

Xposed functionality requires Xposed / EdXposed / LSPosed / Vector to be installed, OR a patched version of the app in question created using Xpatch / LSPatch / NPatch / FPA.

#### Installation with Root

1. Install Happwner and the target app (Happ, v2RayTun, INCY, or another one);
2. Enable Happwner in your Xposed manager and select the scope;
3. Restart Happwner and the selected apps.

#### Installation without Root

1. Install Happwner, the target app, and [NPatch](https://github.com/7723mod/NPatch/releases/tag/v1.0.2) (version **1.0.2** is recommended);
2. In NPatch: *Manage tab* → *"+" button* → *"Select an installed app"* → ***your target*** → *"Integrated" mode* → *"Embed Modules"* → ***Happwner*** → *"Start Patch"*.

**NPatch does not report a successful installation of the patched app.** Tap "Install", wait a few seconds, then check for your app in the list of installed ones.

## Why Happwner?

To give users control over their subscriptions again, improve service transparency, and protect themselves from dishonest resellers.

**Happ** is not just a VPN app, but part of a commercial ecosystem aimed at VPN providers. It gives them extended capabilities by introducing restrictions for users.

* Encrypted links (`happ://crypt5`) force you to install Happ, hide the real subscription URL, and block you from seeing server addresses. You will not know which server you are trusting all of your traffic to, or where it came from. It all comes down to the provider's honesty;
* The hardware identifier (HWID) tightly binds a purchased subscription to a specific device;
* The lack of advanced settings in Happ makes it impossible to hide traffic from questionable providers using proxy chains;
* If a [ProviderID](https://www.happ.su/main/ru/dev-docs/provider-id) is embedded into a `crypt5` link, the app will once a day compare the subscription domain hash, app version, and OS version against the data specified in the seller's dashboard on [happ-proxy.com](https://happ-proxy.com);
* A seller who added a **ProviderID** to an encrypted link gains the ability to [remotely manage the application](https://www.happ.su/main/ru/dev-docs/app-management) without user interaction — force HWID transmission, substitute the subscription URL, disable proxy authentication, and so on:

<details>
<summary>ProviderID capabilities</summary>

* Force-enable HWID transmission even if it is disabled in settings;
* Block manual User-Agent modification while still allowing remote changes;
* Manage local SOCKS and HTTP proxies by reconfiguring or disabling authentication;
* Force users to connect to a specific server when launching Happ;
* Disable global routing in Happ;
* Configure application proxying by adding or removing exclusions;
* Hide VPN servers depending on the connection type (Wi-Fi / mobile network);
* Configure automatic server testing (auto-ping) when opening the app;
* Control the `ping` type (`via Proxy - GET/HEAD`, `TCP`, `ICMP`) and specify a custom URL for server availability checks;
* Change the subscription URL;
* Set the subscription auto-update interval;
* Enable Happ auto-start on device boot;
* Force-update all subscriptions every time the app starts;
* Expand the server list after subscription updates or completely disable collapsing;
* Pin or unpin subscriptions in the main list;
* Change server sorting order alphabetically or by ping;
* Control traffic multiplexing.

**The list is incomplete.** Management parameters are sent through HTTP headers and the response body with each subscription update.
</details>

## Acknowledgements

* **[slavrom21](https://github.com/21slavrom)** for his invaluable contribution to the project (and most of the hard work): reverse-engineering Happ to decrypt profiles and to make Happanion work, refactoring the converters, profile access via Xposed, new animations, Monet support, and many other improvements.
* **[Kasumicic](https://github.com/Kasumicic)** for [Happwner PC](https://github.com/Kasumicic/Happwner_PC), converter testing, fixes, and detailed feedback.

## Terms of Use

You may use, copy, distribute, modify, and build this software for non-commercial purposes, provided that proper attribution is given to the authors (**Omegaplex**, **slavrom21**) and a link to the source repository is included (https://github.com/Omegaplexx/Happwner)

Commercial use, sale, monetization, inclusion in commercial products, or generating profit from this software without the author's permission is prohibited.

## Disclaimer

I assume no obligations toward you as a user, do not guarantee the software will function correctly, and am not responsible for any actions you take.

**Happ** attempts to prevent VPN server reselling by restricting user actions. I remove those restrictions and, in doing so, restore the ability to use servers for purposes beyond the provider's intended limitations. **I condemn any activity that harms a VPN provider's infrastructure and encourage using Happwner responsibly**: the program is intended for personal convenience and for sharing configurations with friends and family. Sharing Internet access is not wrong, as long as you do not create problems for the people providing it.

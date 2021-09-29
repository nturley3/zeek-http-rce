
# Zeek HTTP RCE

## Purpose

This module tags HTTP logs and generates a notice log when it detects possible remote code execution (RCE) attempts over HTTP, similar to how the Zeek SQL injection script works. It's based on common characteristics security analysts observed of RCE attempts of eploits or webshells. It is not based on CVEs, but rather on RCE behaviors found in the "Delivery" and "Installation" phases of the cyber kill chain.

## Installation/Upgrade

This script was written and tested using Zeek 3.0.11.


This is easiest to install through the Zeek package manager:

	zkg refresh
	zkg install nturley3/zeek-http-rce

If you need to upgrade the package:

	zkg refresh
	zkg upgrade nturley3/zeek-http-rce

See the [Zeek Package Manager Docs](https://docs.zeek.org/projects/package-manager/en/stable/quickstart.html) for more information.

## Configuration

No additional Zeek configuration is necessary for this module.

## Generated Outputs

This package adds a tag to the HTTP log:

| `tags` Field Value | Description |
| ----- | ----- |
| HTTP_RCE::URI_RCE | Identifies possible RCE attempts in the URI. |
| HTTP_RCE::POST_RCE | Identifies possible RCE attempts in the post body. (MUST HAVE POST_BODY SCRIPT INSTALLED.) |
| HTTP_RCE::COOKIE_RCE | Identifies possible RCE attempts in the cookie field. (NOT YET IMPLEMENTED.) |

This package generates a notice log:

| Field Name | msg | sub |  src |
| ----- | ----- | ----- | ----- |
| HTTP_RCE::RCE_Victim | An RCE victim was discovered! | Samples of RCE Attempts | The victim IP address |
| HTTP_RCE::RCE_Attacker | An RCE attacker was discovered! | Samples of RCE Attempts | The attacker IP address |

## Usage

A security analyst could treat this similar to the SQL injection notice log or HTTP logs tagged with SQLI. Many RCE attempts will likely be unsuccessful and not require further action. While threat hunting, an analyst may identify targeted web applications or deployed webshells. Often the RCE attempt will trigger the victim system to reach out to another website to download a web shell or other malware, although the RCE could also deliver the webshell itself.

A generated notice log or HTTP tag does not mean the RCE attempt was successful, just that an attempt occurred. This script is prone to producing false positives.

Type: Threat Hunting

## About

Written by @forewarned and @nturley3.

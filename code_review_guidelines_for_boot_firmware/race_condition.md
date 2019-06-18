## Race Condition {#race-condition}

There are two typical race conditions found in firmware:

*   *   1.  Race condition in a data buffer
        2.  Race condition in a register unlocking mechanism.

**Previous Vulnerabilities:**

### Race condition for data buffer {#race-condition-for-data-buffer}

The typical example is the SMM communication buffer. If the check function verified the non-SMRAM copy of communication buffer and then uses it, the attacker may use another CPU thread to perform Time-of-Check/Time-of-Use (TOC/TOU) attack to modify the buffer content after it is checked.

To mitigate this, the communication buffer must be copied into SMRAM before it is checked.

Another example is the motherboard flash content. When [Intel Boot Guard](https://www.intel.com/content/dam/www/public/us/en/documents/white-papers/security-technologies-4th-gen-core-retail-paper.pdf) is enabled, the Authenticated Code Module (ACM) loads Initial Boot Block (IBB) flash into cache and validates the cached copy. An attacker may use the flash programmer to update the IBB flash copy after it is loaded by ACM. This is a variation of a Time-of-Check/Time-of-Use attack.

The IBB cache copy mechanism needs to ensure that no code or data in the IBB flash can be referenced.

### Race condition for register unlock {#race-condition-for-register-unlock}

In 2014, MITRE found a race condition, named [Speed Racer](https://fahrplan.events.ccc.de/congress/2014/Fahrplan/system/attachments/2565/original/speed_racer_whitepaper.pdf), which allows an attacker to subvert a component of the firmware flash protection mechanisms.

Secure code review must verify that SMM code does not leave threads outside of SMRAM when there is flash protection is in an unlocked state.
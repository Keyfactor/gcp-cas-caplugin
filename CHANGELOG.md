 -1.2.0
    - Added Enable Flag
- 1.1.1
    - Fixed bug with Enrollment and Auto Enrollment
    - Fixed issue where only DNS Sans are supported
    - Added additional Logging
- 1.1.0
    - Add support for external SANs/subject (not in CSR)
- 1.0.0
    - First production release of the GCP CAS AnyCA Gateway REST plugin that implements:
        * CA Sync:
            * Download all certificates issued by connected Enterprise tier CAs in GCP CAS (full sync).
            * Download all certificates issued by connected Enterprise tier CAs in GCP CAS issued after a specified time (incremental sync).
        * Certificate enrollment for all published GoDaddy Certificate SKUs:
            * Support certificate enrollment (new keys/certificate).
        * Certificate revocation:
            * Request revocation of a previously issued certificate.

- 1.0.0
    - First production release of the GCP CAS AnyCA Gateway REST plugin that implements:
        * CA Sync:
            * Download all certificates issued by connected Enterprise tier CAs in GCP CAS (full sync).
            * Download all certificates issued by connected Enterprise tier CAs in GCP CAS issued after a specified time (incremental sync).
        * Certificate enrollment for all published GoDaddy Certificate SKUs:
            * Support certificate enrollment (new keys/certificate).
        * Certificate revocation:
            * Request revocation of a previously issued certificate.

## Overview

The [Google Cloud Platform (GCP) CA Services (CAS)](https://cloud.google.com/security/products/certificate-authority-service) AnyCA Gateway REST plugin extends the capabilities of connected GCP CAS CAs to [Keyfactor Command](https://www.keyfactor.com/products/command/) via the Keyfactor AnyCA Gateway REST. The plugin represents a fully featured AnyCA REST Plugin with the following capabilies:

* CA Sync:
    * Download all certificates issued by connected Enterprise tier CAs in GCP CAS.
* Certificate enrollment for all published GoDaddy Certificate SKUs:
    * Support certificate enrollment (new keys/certificate).
* Certificate revocation:
    * Request revocation of a previously issued certificate.

> **🚧 Disclaimer** 
>
> CA Sync and Revocation is not directly supported for [DevOps Tier](https://cloud.google.com/certificate-authority-service/docs/tiers) Certificate Authority Pools.
> 
> DevOps tier CA Pools don't offer listing, describing, or revoking certificates.

## Requirements

The GCP CAS AnyCA Gateway REST plugin connects to and authenticates with GCP CAS implicitly using [Application Default Credentials](https://cloud.google.com/docs/authentication/application-default-credentials). 



## Gateway Registration

The Gateway Registration tab configures the CA certificate of the target CA in GCP CAS.

## Certificate Template Creation Step

asdf

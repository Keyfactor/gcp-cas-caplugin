## Overview

The [Google Cloud Platform (GCP) CA Services (CAS)](https://cloud.google.com/security/products/certificate-authority-service) AnyCA Gateway REST plugin extends the capabilities of connected GCP CAS CAs to [Keyfactor Command](https://www.keyfactor.com/products/command/) via the Keyfactor AnyCA Gateway REST. The plugin represents a fully featured AnyCA REST Plugin with the following capabilies:

* CA Sync:
    * Download all certificates issued by connected Enterprise tier CAs in GCP CAS (full sync).
    * Download all certificates issued by connected Enterprise tier CAs in GCP CAS issued after a specified time (incremental sync).
* Certificate enrollment for all published GoDaddy Certificate SKUs:
    * Support certificate enrollment (new keys/certificate).
* Certificate revocation:
    * Request revocation of a previously issued certificate.

> **🚧 Disclaimer** 
>
> CA Sync and Revocation is not supported for [DevOps Tier](https://cloud.google.com/certificate-authority-service/docs/tiers) Certificate Authority Pools.
> 
> DevOps tier CA Pools don't offer listing, describing, or revoking certificates.

## Requirements

### Application Default Credentials

The GCP CAS AnyCA Gateway REST plugin connects to and authenticates with GCP CAS implicitly using [Application Default Credentials](https://cloud.google.com/docs/authentication/application-default-credentials). This means that all authentication-related configuration of the GCP CAS AnyCA Gateway REST plugin is implied by the environment where the AnyCA Gateway REST itself is running.

Please refer to [Google's documentation](https://cloud.google.com/docs/authentication/provide-credentials-adc) to configure ADC on the server running the AnyCA Gateway REST.

> The easiest way to configure ADC for non-production environments is to use [User Credentials](https://cloud.google.com/docs/authentication/provide-credentials-adc#local-dev).
>
> For production environments that use an ADC method requiring the `GOOGLE_APPLICATION_CREDENTIALS` environment variable, you must ensure the following:
>
> 1. The service account that the AnyCA Gateway REST runs under must have read permission to the GCP credential JSON file.
> 2. You must set the `GOOGLE_APPLICATION_CREDENTIALS` environment variable for the Windows Service running the AnyCA Gateway REST using the [Windows registry editor](https://learn.microsoft.com/en-us/troubleshoot/windows-server/performance/windows-registry-advanced-users).
>     * Refer to the [HKLM\SYSTEM\CurrentControlSet\Services Registry Tree](https://learn.microsoft.com/en-us/windows-hardware/drivers/install/hklm-system-currentcontrolset-services-registry-tree) docs

If the selected ADC mechanism is [Service Account Key](https://cloud.google.com/docs/authentication/provide-credentials-adc#wlif-key), it's recommended that a [custom role is created](https://cloud.google.com/iam/docs/creating-custom-roles) that has the following minimum permissions:

* `privateca.certificateTemplates.list`
* `privateca.certificateTemplates.use`
* `privateca.certificateAuthorities.get`
* `privateca.certificates.create`
* `privateca.certificates.get`
* `privateca.certificates.list`
* `privateca.certificates.update`

> The built-in CA Service Operation Manager `roles/privateca.caManager` role can also be used, but is more permissive than a custom role with the above permissions.

### Root CA Configuration

Both the Keyfactor Command and AnyCA Gateway REST servers must trust the root CA, and if applicable, any subordinate CAs for all features to work as intended. Download the CA Certificate (and chain, if applicable) from GCP [CAS](https://console.cloud.google.com/security/cas), and import them into the appropriate certificate store on the AnyCA Gateway REST server.

* **Windows** - If the AnyCA Gateway REST is running on a Windows host, the root CA and applicable subordinate CAs must be imported into the Windows certificate store. The certificates can be imported using the Microsoft Management Console (MMC) or PowerShell. 
* **Linux** - If the AnyCA Gateway REST is running on a Linux host, the root CA and applicable subordinate CAs must be present in the root CA certificate store. The location of this store varies per distribution, but is most commonly `/etc/ssl/certs/ca-certificates.crt`. The following is documentation on some popular distributions.
    * [Ubuntu - Managing CA certificates](https://ubuntu.com/server/docs/install-a-root-ca-certificate-in-the-trust-store)
    * [RHEL 9 - Using shared system certificates](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/securing_networks/using-shared-system-certificates_securing-networks#using-shared-system-certificates_securing-networks)
    * [Fedora - Using Shared System Certificates](https://docs.fedoraproject.org/en-US/quick-docs/using-shared-system-certificates/)

> The root CA and intermediate CAs must be trusted by both the Command server _and_ AnyCA Gateway REST server.

## Gateway Registration

The Gateway Registration tab configures the root or issuing CA certificate for the respective CA in GCP CAS. The certificate selected here should be the issuing CA identified in the [Root CA Configuration](#root-ca-configuration) step.

> If you have several CAs in GCP CAS, you must define an individual Certificate Authority for each CA in the AnyCA Gateway REST.

## Certificate Template Creation Step

Define [Certificate Profiles](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/AddCP-Gateway.htm) and [Certificate Templates](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/AddCA-Gateway.htm) for the Certificate Authority as required. One Certificate Profile must be defined per Certificate Template. It's recommended that each Certificate Profile be named after the Product ID.

The GCP CAS AnyCA Gateway REST plugin downloads all Certificate Templates in the configured GCP Region/Project and interprets them as 'Product IDs' in the Gateway Portal.

> For example, if the connected GCP project has the following Certificate Templates:
> 
> * `ServerAuth`
> * `ClientAuth`
>
> The `Edit Templates` > `Product ID` dialog dropdown will show the following available 'ProductIDs':
>
> * `Default` -> Don't use a certificate template when enrolling certificates with this Template.
> * `ServerAuth` -> Use the `ServerAuth` certificate template in GCP when enrolling certificates with this Template.
> * `ClientAuth` -> Use the `ClientAuth` certificate template in GCP when enrolling certificates with this Template.

## Mechanics

### Synchronization

The GCP CAS AnyCA Gateway REST plugin uses the [`ListCertificatesRequest` RPC](https://cloud.google.com/certificate-authority-service/docs/reference/rpc/google.cloud.security.privateca.v1#google.cloud.security.privateca.v1.ListCertificatesRequest) when synchronizing certificates from GCP. At the time the latest release, this RPC does not enable granularity to list certificates issued by a particular CA. As such, the CA Synchronization job implemented by the plugin will _always_ download all certificates issued by _any CA_ in the CA Pool. This disclaimer doesn't apply to configurations where each CA in GCP CAS is managed by individual CA Pools.

> Friendly reminder to always follow the [GCP CAS best practices](https://cloud.google.com/certificate-authority-service/docs/best-practices)

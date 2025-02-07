<h1 align="center" style="border-bottom: none">
    GCP CAS AnyCA Gateway REST Plugin
</h1>

<p align="center">
  <!-- Badges -->
<img src="https://img.shields.io/badge/integration_status-production-3D1973?style=flat-square" alt="Integration Status: production" />
<a href="https://github.com/Keyfactor/gcp-cas-caplugin/releases"><img src="https://img.shields.io/github/v/release/Keyfactor/gcp-cas-caplugin?style=flat-square" alt="Release" /></a>
<img src="https://img.shields.io/github/issues/Keyfactor/gcp-cas-caplugin?style=flat-square" alt="Issues" />
<img src="https://img.shields.io/github/downloads/Keyfactor/gcp-cas-caplugin/total?style=flat-square&label=downloads&color=28B905" alt="GitHub Downloads (all assets, all releases)" />
</p>

<p align="center">
  <!-- TOC -->
  <a href="#support">
    <b>Support</b>
  </a> 
  ·
  <a href="#requirements">
    <b>Requirements</b>
  </a>
  ·
  <a href="#installation">
    <b>Installation</b>
  </a>
  ·
  <a href="#license">
    <b>License</b>
  </a>
  ·
  <a href="https://github.com/orgs/Keyfactor/repositories?q=anycagateway">
    <b>Related Integrations</b>
  </a>
</p>


The [Google Cloud Platform (GCP) CA Services (CAS)](https://cloud.google.com/security/products/certificate-authority-service) AnyCA Gateway REST plugin extends the capabilities of connected GCP CAS CAs to [Keyfactor Command](https://www.keyfactor.com/products/command/) via the Keyfactor AnyCA Gateway REST. The plugin represents a fully featured AnyCA REST Plugin with the following capabilies:

* CA Sync:
    * Download all certificates issued by connected Enterprise tier CAs in GCP CAS (full sync).
    * Download all certificates issued by connected Enterprise tier CAs in GCP CAS issued after a specified time (incremental sync).
* Certificate enrollment for all published GCP Certificate SKUs:
    * Support certificate enrollment (new keys/certificate).
    * Support auto-enrollment (subject/SANs outside of the CSR)
* Certificate revocation:
    * Request revocation of a previously issued certificate.

> **🚧 Disclaimer** 
>
> The GCP CAS AnyCA Gateway REST plugin is **not** supported for [DevOps Tier](https://cloud.google.com/certificate-authority-service/docs/tiers) Certificate Authority Pools.
> 
> DevOps tier CA Pools don't offer listing, describing, or revoking certificates.

## Compatibility

The GCP CAS AnyCA Gateway REST plugin is compatible with the Keyfactor AnyCA Gateway REST 24.2 and later.

## Support
The GCP CAS AnyCA Gateway REST plugin is supported by Keyfactor for Keyfactor customers. If you have a support issue, please open a support ticket with your Keyfactor representative. If you have a support issue, please open a support ticket via the Keyfactor Support Portal at https://support.keyfactor.com. 

> To report a problem or suggest a new feature, use the **[Issues](../../issues)** tab. If you want to contribute actual bug fixes or proposed enhancements, use the **[Pull requests](../../pulls)** tab.

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

## Installation

1. Install the AnyCA Gateway REST per the [official Keyfactor documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/InstallIntroduction.htm).

2. On the server hosting the AnyCA Gateway REST, download and unzip the latest [GCP CAS AnyCA Gateway REST plugin](https://github.com/Keyfactor/gcp-cas-caplugin/releases/latest) from GitHub.

3. Copy the unzipped directory (usually called `net6.0`) to the Extensions directory:

    ```shell
    Program Files\Keyfactor\AnyCA Gateway\AnyGatewayREST\net6.0\Extensions
    ```

    > The directory containing the GCP CAS AnyCA Gateway REST plugin DLLs (`net6.0`) can be named anything, as long as it is unique within the `Extensions` directory.

4. Restart the AnyCA Gateway REST service.

5. Navigate to the AnyCA Gateway REST portal and verify that the Gateway recognizes the GCP CAS plugin by hovering over the ⓘ symbol to the right of the Gateway on the top left of the portal.

## Configuration

1. Follow the [official AnyCA Gateway REST documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/AddCA-Gateway.htm) to define a new Certificate Authority, and use the notes below to configure the **Gateway Registration** and **CA Connection** tabs:

    * **Gateway Registration**

        The Gateway Registration tab configures the root or issuing CA certificate for the respective CA in GCP CAS. The certificate selected here should be the issuing CA identified in the [Root CA Configuration](#root-ca-configuration) step.

        > If you have several CAs in GCP CAS, you must define an individual Certificate Authority for each CA in the AnyCA Gateway REST.

    * **CA Connection**

        Populate using the configuration fields collected in the [requirements](#requirements) section.

        * **LocationId** - The GCP location ID where the project containing the target GCP CAS CA is located. For example, 'us-central1'. 
        * **ProjectId** - The GCP project ID where the target GCP CAS CA is located 
        * **CAPool** - The CA Pool ID in GCP CAS to use for certificate operations. If the CA Pool has resource name `projects/my-project/locations/us-central1/caPools/my-pool`, this field should be set to `my-pool` 
        * **CAId** - The CA ID of a CA in the same CA Pool as CAPool. For example, to issue certificates from a CA with resource name `projects/my-project/locations/us-central1/caPools/my-pool/certificateAuthorities/my-ca`, this field should be set to `my-ca`. 
        * **Enabled** - Flag to Enable or Disable gateway functionality. Disabling is primarily used to allow creation of the CA prior to configuration information being available. 

2. Define [Certificate Profiles](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/AddCP-Gateway.htm) and [Certificate Templates](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/AddCA-Gateway.htm) for the Certificate Authority as required. One Certificate Profile must be defined per Certificate Template. It's recommended that each Certificate Profile be named after the Product ID.

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

3. Follow the [official Keyfactor documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/AddCA-Keyfactor.htm) to add each defined Certificate Authority to Keyfactor Command and import the newly defined Certificate Templates.



## License

Apache License 2.0, see [LICENSE](LICENSE).

## Related Integrations

See all [Keyfactor Any CA Gateways (REST)](https://github.com/orgs/Keyfactor/repositories?q=anycagateway).
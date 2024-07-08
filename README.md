<h1 align="center" style="border-bottom: none">
    gcp-cas-ca AnyCA Gateway REST Plugin
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



## Compatibility

The gcp-cas-ca AnyCA Gateway REST plugin is compatible with the Keyfactor AnyCA Gateway REST 24.2 and later.

## Support
The gcp-cas-ca AnyCA Gateway REST plugin is supported by Keyfactor for Keyfactor customers. If you have a support issue, please open a support ticket with your Keyfactor representative. If you have a support issue, please open a support ticket via the Keyfactor Support Portal at https://support.keyfactor.com. 

> To report a problem or suggest a new feature, use the **[Issues](../../issues)** tab. If you want to contribute actual bug fixes or proposed enhancements, use the **[Pull requests](../../pulls)** tab.

## Requirements

Authentication to


asdf



## Installation

1. Install the AnyCA Gateway REST per the [official Keyfactor documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/InstallIntroduction.htm).

2. On the server hosting the AnyCA Gateway REST, download and unzip the latest [gcp-cas-ca AnyCA Gateway REST plugin](https://github.com/Keyfactor/gcp-cas-caplugin/releases/latest) from GitHub.

3. Copy the unzipped directory (usually called `net6.0`) to the Extensions directory:

    ```shell
    Program Files\Keyfactor\AnyCA Gateway\AnyGatewayREST\net6.0\Extensions
    ```

    > The directory containing the gcp-cas-ca AnyCA Gateway REST plugin DLLs (`net6.0`) can be named anything, as long as it is unique within the `Extensions` directory.

4. Restart the AnyCA Gateway REST service.

5. Navigate to the AnyCA Gateway REST portal and verify that the Gateway recognizes the gcp-cas-ca plugin by hovering over the ⓘ symbol to the right of the Gateway on the top left of the portal.

## Configuration

1. Follow the [official AnyCA Gateway REST documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/AddCA-Gateway.htm) to define a new Certificate Authority, and use the notes below to configure the **Gateway Registration** and **CA Connection** tabs:

    * **Gateway Registration**


        asdf



    * **CA Connection**

        Populate using the configuration fields collected in the [requirements](#requirements) section.



        * **LocationId** - The GCP location ID where the project containing the target GCP CAS CA is located. For example, 'us-central1'. 
        * **ProjectId** - The GCP project ID where the target GCP CAS CA is located 
        * **CAPool** - The CA Pool ID in GCP CAS to use for certificate operations. If the CA Pool has resource name `projects/my-project/locations/us-central1/caPools/my-pool`, this field should be set to `my-pool` 
        * **CAId** - The CA ID of a CA in the same CA Pool as CAPool. For example, to issue certificates from a CA with resource name `projects/my-project/locations/us-central1/caPools/my-pool/certificateAuthorities/my-ca`, this field should be set to `my-ca`. 
        * **Enabled** - Flag to Enable or Disable gateway functionality. Disabling is primarily used to allow creation of the CA prior to configuration information being available. 

2. asdf



3. Follow the [official Keyfactor documentation](https://software.keyfactor.com/Guides/AnyCAGatewayREST/Content/AnyCAGatewayREST/AddCA-Keyfactor.htm) to add each defined Certificate Authority to Keyfactor Command and import the newly defined Certificate Templates.

4. In Keyfactor Command (v12.3+), for each imported Certificate Template, follow the [official documentation](https://software.keyfactor.com/Core-OnPrem/Current/Content/ReferenceGuide/Configuring%20Template%20Options.htm) to define enrollment fields for each of the following parameters:






## License

Apache License 2.0, see [LICENSE](LICENSE).

## Related Integrations

See all [Keyfactor Any CA Gateways (REST)](https://github.com/orgs/Keyfactor/repositories?q=anycagateway).
## Overview

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

## Google Certificate Authority Service (CAS) Setup for Keyfactor Integration

### Overview

This guide provides a step-by-step approach to setting up **Google Certificate Authority Service (CAS)** and integrating it with **Keyfactor** for certificate enrollment. Since Google CAS does not extract metadata from Certificate Signing Requests (CSRs), certificate templates must be defined in CAS to allow Keyfactor to request certificates correctly. While **templates are preferred**, they are **not required**—if the **Default** Product ID is used, certificates will be generated based on the CA settings instead of a template.

---

### Prerequisites

Before setting up Google CAS, ensure you have:

- A **Google Cloud account** with billing enabled
- The **Certificate Authority Service API** activated
- Required **IAM permissions**:
  - `roles/privateca.admin` (for managing CAS)
  - `roles/privateca.certificateManager` (for issuing certificates)

---

### Google CAS Setup

#### **Step 1: Enable Certificate Authority Service API**

```sh
gcloud services enable privateca.googleapis.com
```

#### **Step 2: Create a Root Certificate Authority (CA)**

```sh
gcloud privateca roots create my-root-ca \
  --location=us-central1 \
  --key-algorithm=rsa-pkcs1-4096-sha256 \
  --subject="CN=My Root CA, O=My Organization, C=US" \
  --use-preset-profile=ROOT_CA_DEFAULT \
  --bucket=my-ca-bucket
```

#### **Step 3: Define Certificate Key Usage and Extended Key Usage**

Certificate Key Usage and Extended Key Usage define how the certificates issued by the CA can be used. These must be set at the **CA policy level** or within a **certificate template**.

##### **Option 1: Define Key Usage in CA Policy**

Create a CA policy file (`ca-policy.json`):

```json
{
  "baselineValues": {
    "keyUsage": {
      "baseKeyUsage": {
        "digitalSignature": true,
        "keyEncipherment": true
      },
      "extendedKeyUsage": {
        "serverAuth": true,
        "clientAuth": true
      }
    }
  }
}
```

Apply the policy when creating the CA:

```sh
gcloud privateca roots create my-root-ca \
  --location=us-central1 \
  --key-algorithm=rsa-pkcs1-4096-sha256 \
  --subject="CN=My Root CA, O=My Organization, C=US" \
  --use-preset-profile=ROOT_CA_DEFAULT \
  --bucket=my-ca-bucket \
  --ca-policy=ca-policy.json
```

##### **Option 2: Define Key Usage in a Certificate Template (Preferred but Not Required)**

If using a certificate template, create a policy file (`cert-template-policy.json`):

```json
{
  "predefinedValues": {
    "keyUsage": {
      "baseKeyUsage": {
        "digitalSignature": true,
        "keyEncipherment": true
      },
      "extendedKeyUsage": {
        "serverAuth": true,
        "clientAuth": true
      }
    }
  }
}
```

Create the template:

```sh
gcloud privateca templates create my-cert-template \
  --location=us-central1 \
  --policy-file=cert-template-policy.json
```

If a **template is not used**, certificates will be generated **directly based on CA settings**.

---

### **Certificate Signing Request (CSR) Handling in Google CAS**

- **CSR is only used for the private key proof-of-possession.**
- **All certificate metadata (e.g., Subject, SANs) must be provided via configuration files or templates.**
- **Additional fields in the CSR are ignored by Google CAS.**

#### **Example: Issuing a Certificate with a CSR**

##### **1. Generate a CSR**

```sh
openssl req -new -newkey rsa:2048 -nodes -keyout my-key.pem -out my-csr.pem -subj "/CN=ignored.example.com"
```

##### **2. Define Certificate Configuration**

```json
{
  "lifetime": "2592000s",
  "subjectConfig": {
    "subject": {
      "commonName": "mydomain.com",
      "organization": "My Organization",
      "countryCode": "US"
    },
    "subjectAltName": {
      "dnsNames": ["mydomain.com", "www.mydomain.com"]
    }
  },
  "keyUsage": {
    "baseKeyUsage": {
      "digitalSignature": true,
      "keyEncipherment": true
    },
    "extendedKeyUsage": {
      "serverAuth": true
    }
  }
}
```

##### **3. Issue the Certificate**

```sh
gcloud privateca certificates create my-cert \
  --issuer-pool=my-root-ca \
  --csr my-csr.pem \
  --config-file cert-config.json \
  --location=us-central1
```

---

### **Integrating Keyfactor with Google CAS**

#### **Why Use Certificate Templates?**

- **Google CAS does not extract metadata from CSRs.**
- **Keyfactor prefers enrollment of certificates via predefined templates** to ensure all attributes (e.g., Subject, SANs) are correctly applied.
- **Prevents unauthorized data injection via CSRs.**
- **If no template is used, certificates will be issued based on CA settings using the Default Product ID.**

#### **Step 1: Create a Certificate Template for Keyfactor (Preferred but Not Required)**

Create a **certificate template policy file** (`keyfactor-template-policy.json`):

```json
{
  "predefinedValues": {
    "keyUsage": {
      "baseKeyUsage": {
        "digitalSignature": true,
        "keyEncipherment": true
      },
      "extendedKeyUsage": {
        "serverAuth": true,
        "clientAuth": true
      }
    }
  },
  "identityConstraints": {
    "allowSubjectPassthrough": true,
    "allowSubjectAltNamesPassthrough": true
  }
}
```

Create the template:

```sh
gcloud privateca templates create keyfactor-template \
  --location=us-central1 \
  --policy-file=keyfactor-template-policy.json
```

If using the **Default** Product ID in Keyfactor, Google CAS will generate certificates directly from CA settings **without requiring a template**.

---



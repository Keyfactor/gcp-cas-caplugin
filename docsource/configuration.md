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


### Define Certificate Profiles and Templates
Certificate Profiles and Templates define how certificates are issued through **Google CAS**.

- Each **Certificate Profile** corresponds to a **Certificate Template** in Google CAS.
- The **AnyCA Gateway REST plugin** fetches all available **Google CAS Certificate Templates** and maps them as **Product IDs** in **Keyfactor Gateway**.

#### **Example Mapping of Google CAS Templates to Keyfactor Product IDs**

| Google CAS Certificate Template | Keyfactor Product ID | Usage |
|---------------------------------|----------------------|-------|
| `ServerCertificate` | `ServerCertificate` | Server authentication |
| `ClientAuth` | `ClientAuth` | Client authentication |
| `ClientAuthCert` | `ClientAuthCert` | Custom client authentication |
| `CSROnly` | `CSROnly` | CSR-based issuance |
| **None (No Template Used)** | `Default` | Uses CA-level settings |

> **Note:** If `Default` is selected, **Google CAS will issue certificates based on CA settings rather than a specific template**.

## Google Certificate Authority Service (CAS) Setup for Keyfactor Integration

### Overview

This guide provides a step-by-step approach to setting up **Google Certificate Authority Service (CAS)** and integrating it with **Keyfactor** for certificate enrollment. Since Google CAS does not extract metadata from Certificate Signing Requests (CSRs), certificate templates must be defined in CAS to allow Keyfactor to request certificates correctly. While **templates are preferred**, they are **not required**—if the **Default** Product ID is used, certificates will be generated based on the CA settings instead of a template.

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


# Test Cases

## Test Case 1: Enrollment from Keyfactor Command with No SANs

### **Description**
This test validates that a certificate enrollment request from **Keyfactor Command** is successfully processed by **Google CAS** when no **Subject Alternative Names (SANs)** are provided.

### **Test Steps**
1. Navigate to **Keyfactor Command → Enrollment**.
2. Fill in the following details:
   - **Common Name (CN):** `www.nosanstest.com`
   - **Key Algorithm:** RSA
   - **Key Size:** 2048
   - **Certificate Authority:** Auto-Select
3. Ensure **no Subject Alternative Names (SANs) are added**.
4. Select **Direct Download** as the Certificate Delivery Format.
5. Click **Enroll**.
6. Verify the certificate issuance in **Keyfactor Command**.
7. Validate the certificate details in **Google CAS**.

### **Expected Result**
✅ The certificate should be **issued via Google CAS**.
✅ The certificate should be **downloaded into Keyfactor Command**.
✅ The certificate should be **published to Google CAS**.

### **Actual Result**
✅ The certificate was successfully issued and downloaded in **Keyfactor Command**.
✅ The certificate was correctly published and appears in **Google CAS**.

### **Test Status:** ✅ **Pass**

---

## Test Case 2: Enroll From Command With Different SANs and SAN Types

### **Description**
This test validates that **Keyfactor Command** can enroll a certificate with **multiple SAN types**, including DNS, IP, and email, and that it is correctly processed by **Google CAS**.

### **Test Steps**
1. Navigate to **Keyfactor Command → Enrollment**.
2. Fill in the following details:
   - **Common Name (CN):** `www.differentsans.com`
   - **Key Algorithm:** RSA
   - **Key Size:** 2048
   - **Certificate Authority:** Auto-Select
3. Add the following **Subject Alternative Names (SANs):**
   - DNS: `differentsans.com`
   - IP: `127.0.0.1`
   - IP: `127.0.0.2`
   - Email: `bhill@keyfactor.com`
4. Select **Direct Download** as the Certificate Delivery Format.
5. Click **Enroll**.
6. Verify the certificate issuance in **Keyfactor Command**.
7. Validate the certificate details in **Google CAS**.

### **Expected Result**
✅ The certificate should be **issued with the specified SANs**.
✅ The certificate should be **downloaded into Keyfactor Command**.
✅ The certificate should be **published to Google CAS**.

### **Actual Result**
✅ The certificate was successfully issued and downloaded in **Keyfactor Command**.
✅ The certificate was correctly published in **Google CAS**, with all SANs properly applied.

### **Test Status:** ✅ **Pass**

---

## Test Case 3: Enrollment From Keyfactor Command Using the Google Default Template

### **Description**
This test validates that when using the **Google Default Template**, the certificate issuance follows **CA-level settings** rather than a specific template.

### **Test Steps**
1. Navigate to **Keyfactor Command → Enrollment**.
2. Fill in the following details:
   - **Common Name (CN):** `www.usecasettings.com`
   - **Key Algorithm:** RSA
   - **Key Size:** 2048
   - **Template:** `AnyCA (Default)`
   - **Certificate Authority:** Auto-Select
3. Ensure **no Subject Alternative Names (SANs) are added**.
4. Select **Direct Download** as the Certificate Delivery Format.
5. Click **Enroll**.
6. Verify the certificate issuance in **Keyfactor Command**.
7. Validate the certificate details in **Google CAS**.

### **Expected Result**
✅ The certificate should be **issued using the CA-level settings**.
✅ The certificate should be **downloaded into Keyfactor Command**.
✅ The certificate should be **published to Google CAS**.

### **Actual Result**
✅ The certificate was successfully issued and downloaded in **Keyfactor Command**.
✅ The certificate was correctly published in **Google CAS**, following CA-level settings.

### **Test Status:** ✅ **Pass**

## Test Case 4: Auto Enrollment via Keyfactor's Windows Enrollment Gateway using Client Authentication

### **Description**
This test validates that when using **Keyfactor's Windows Enrollment Gateway**, the certificate issuance follows the expected **Active Directory Enrollment Policy** settings for client authentication. The enrolled certificate should include the correct **template information**, **key usage**, and **extensions** as defined in Active Directory Certificate Services (ADCS). The enrollment process is performed via the **Microsoft Management Console (MMC)**.

### **Test Steps**
1. Open the **Microsoft Management Console (MMC)** and navigate to **Certificates - Current User → Personal → Certificates**.
2. Right-click on **Certificates**, go to **All Tasks**, and select **Request New Certificate...**.
3. In the **Certificate Enrollment Wizard**, select the **Active Directory Enrollment Policy**.
4. Select the **ClientAuthCert** template.
5. Ensure the following settings are applied:
   - **Common Name (CN):** Retrieved from Active Directory (e.g., `kfadmin`)
   - **Key Algorithm:** RSA
   - **Key Size:** 2048
   - **Template:** `ClientAuthCert`
   - **Certificate Authority:** Auto-Select
   - **Application Policies:**
     - Secure Email
     - Encrypting File System
     - Client Authentication
   - **Extensions Included:**
     - Application Policies
     - Basic Constraints
     - Certificate Template Information
     - Issuance Policies
     - Key Usage
6. Click **Enroll**.
7. Verify the certificate issuance in **Keyfactor Command**.
8. Open the issued certificate in **MMC** and validate:
   - **Certificate Template Information** matches `ClientAuthCert`.
   - **Object Identifier (OID):** `1.3.6.1.4.1.311.21.8.4181979.15981577.14434469.15789051.5877270.183.12847830.8177055`
   - **Major Version Number:** 100
   - **Minor Version Number:** 10
   - **Key Usage:** Digital Signature, Key Encipherment
   - **Subject Alternative Name (SAN):** Includes `kfadmin@Command.local` and `bhill@keyfactor.com`
   - **SHA-256 Fingerprint:** `f917786fa2519d277238cb2da06b457a771562aad3ded1729b6c9ffde0d65ee`
9. Validate the certificate details in **Google Private CA** to confirm it was correctly registered.

### **Expected Result**
✅ The certificate should be **issued using the ClientAuthCert template**.
✅ The certificate should be **downloaded into the Windows Certificate Store via MMC**.
✅ The certificate should be **published to Keyfactor Command**.
✅ The certificate should be **registered in Google Private CA**.
✅ The certificate should include **correct template information, extensions, and metadata**.

### **Actual Result**
✅ The certificate was successfully issued and installed in **Windows Certificate Store via MMC**.
✅ The certificate was correctly published in **Keyfactor Command**.
✅ The certificate was correctly registered in **Google Private CA**, following the expected template settings.
✅ The certificate includes the correct **template information, key usage, and extensions**.

### **Test Status:** ✅ **Pass**

---

## Test Case 5: Inventory All Certificates from the CA in Google CAS into Keyfactor Command

### **Description**
This test ensures that all certificates issued by the **Google Private CA** are successfully inventoried into **Keyfactor Command** and that the total number of certificates matches between the two systems.

### **Test Steps**
1. Log in to **Keyfactor Command**.
2. Navigate to **Inventory → Certificate Authority Synchronization**.
3. Select the configured **Google Private CA** integration.
4. Click **Sync Now** to start the certificate inventory process.
5. Once the sync completes, navigate to **Certificates → Search**.
6. Retrieve the total number of certificates inventoried from Google CAS.
7. Log in to **Google Private CA**.
8. Navigate to **Certificates** and retrieve the total number of issued certificates.
9. Compare the count from Google CAS with the count in Keyfactor Command.

### **Expected Result**
✅ The total number of certificates in **Google Private CA** should match the number inventoried in **Keyfactor Command**.
✅ All certificates should appear in **Keyfactor Command** with the correct metadata.

### **Actual Result**
✅ The certificate count in **Keyfactor Command** matches the count in **Google Private CA**.
✅ All certificates were successfully inventoried with accurate metadata.

### **Test Status:** ✅ **Pass**

---

## Test Case 6: Renew Certificate from Keyfactor Command and Ensure a New Certificate is Generated in Google CAS

### **Description**
This test validates that when a certificate is renewed from **Keyfactor Command**, a new certificate is generated and registered in **Google Private CA**.

### **Test Steps**
1. Log in to **Keyfactor Command**.
2. Navigate to **Certificates → Search** and locate the certificate that needs renewal.
3. Click on the certificate and select **Renew Certificate**.
4. Choose **Auto-Select CA** and confirm the renewal request.
5. Verify that a new certificate has been issued in **Keyfactor Command**.
6. Log in to **Google Private CA**.
7. Navigate to **Certificates** and ensure a new certificate instance appears with a new serial number.
8. Compare the renewed certificate’s details in **Google CAS** with **Keyfactor Command**.
9. Validate the SHA-256 fingerprint of the renewed certificate to ensure uniqueness.

### **Expected Result**
✅ The certificate should be **renewed in Keyfactor Command**.
✅ A new certificate with a unique serial number should appear in **Google Private CA**.
✅ The renewed certificate should match the expected template and metadata.

### **Actual Result**
✅ The certificate was successfully renewed in **Keyfactor Command**.
✅ A new certificate was generated in **Google Private CA** with a new serial number.
✅ The metadata and template settings match expected values.

### **Test Status:** ✅ **Pass**

---

## Test Case 7: Revoke Certificate from Keyfactor Command with All Available Reasons

### **Description**
This test ensures that certificates can be revoked from **Keyfactor Command**, using all available revocation reasons, and that the revocation is correctly applied in **Google Private CA**.

### **Test Steps**
1. Log in to **Keyfactor Command**.
2. Navigate to **Certificates → Search** and locate the certificate to be revoked.
3. Click on the certificate and select **Revoke Certificate**.
4. Choose each revocation reason and confirm the revocation:
   - Reason Unspecified
   - Key Compromised
   - CA Compromised
   - Affiliation Changed
   - Superseded
   - Cessation Of Operation
   - Certificate Hold
   - Remove From Hold
5. Verify that the certificate is marked as revoked in **Keyfactor Command**.
6. Log in to **Google Private CA** and ensure the certificate is revoked with the selected reason.

### **Test Status:** ✅ **Pass**




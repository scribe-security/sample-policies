# Sample Policies

This repo includes samples of policy configuraions for Scribe's ```valint``` tool.

## Preparation

1. Install valint:

    ```bash
    curl -sSfL https://get.scribesecurity.com/install.sh  | sh -s -- -t valint
    ```

2. Clone this repo.

## Policy Catalogue

Policy list below is copied from the `opapi` repo. Each policy in the table that has an example in this repo has a link to the policy description.

| Policy | Description | Attestations |
| --- | --- | --- |
| [Artifact Signed](#artifact-signed) | Verify that the artifact is signed (also verify identity and CA identity) | SBOM |
| [Blacklist Packages](#blacklist-packages) | Verify that banned packages are not in SBOM | SBOM |
| [Required Packages](#required-packages) (e.g. license artifact) | Verify that required packages or files are in SBOM | SBOM |
| [Banned Licenses](#banned-licenses) | Verify that banned licenses are not in SBOM | SBOM |
| [Complete Licenses](#complete-licenses) | Verify that all packages have a license | SBOM |
| [Fresh SBOM](#fresh-sbom) | Verify that SBOM is fresh | SBOM |
| [Fresh Image](#fresh-image) | Verify that image is fresh - (rebuilt from latest) | Image SBOM |
| Image Does Not Allow Shell Access | Verify that the image has an entrypoint | Image SBOM |
| Image Build Did Not Run blind scripts | Verify that the image build commands did not include curl | bash | Image SBOM |
| Image Included Required Lables | Verify that the image has required labels. Used to enforce best practices such as labling the image with the git-commit used to build it (provenance) | Image SBOM |
| [Do Not Allow Huge Images](#large-image) | Verify that the image is not too large | Image SBOM |
| Coding Permissions | Verify that allowed identities have modified specific files in a repo | Git SBOM |
| Merging Permissions | Verify that allowed identities have merged to main  | Git SBOM |
| Signed Commits | Verify all commits are signed | Git SBOM |
| [No Commits To Main](#no-commits-to-main) | Verify that no commits are made to main | Git SBOM |
| Verify Provenance Exists | Verify that provenance for an artifact exists | SLSA-Prov |
| [Verify Use of Specific Builder](#builder-name) | Verify that a specific builder was used to build an artifact | SLSA-Prov |
| Banned Builder Dependencies | Verify that the builder used to build an artifact does not have banned dependencies (such as an old openSSL version) | SLSA-Prov |
| Verify Build Time | Verify that the build was done in a specific time window (working day)| SLSA-Prov |
| Verify Byproducts Produced | Verify that specific byproducts are produced (e.g. testing, coverage, static analysis reports) | SLSA-Prov |
| [No Critical CVEs](#no-critical-cves) | Verify that the artifact does not have any ctitical CVEs | SARIF |
| [Limit High CVEs](#limit-high-cves) | Verify that the artifact does not have more than a specific number of high CVEs | SARIF |
| [Do Not Allow Specific CVEs](#do-not-allow-specific-cves) | Verify that the artifact does not have specific CVEs | SARIF |
| No Static Analysis Errors | Verify that the artifact does not have static analysis errors | SARIF |
| Limit Static Analysis Warnings | Verify that the artifact does not have more than a specific number of static analysis warnings | SARIF |
| Do Not Allow Specific Static Analysis Rules | Verify that the artifact does not have specific static analysis warnings | SARIF |
| No Package Downgrading | Verify that the artifact does not have any package downgrades | Two SBOMs |
| No License Modification | Verify that the artifact does not have any license modifications | Two SBOMs |
| Verify Source Integrity | Verify that the artifact source code has not been modified | Two SBOMs |
| Verify Dependencies Integrity (aka Verify specific files and folders integrity) | Verify that specific files or folders have not been modified | Two SBOMs |

### SBOMs

#### Artifact Signed

This policy verifies that the SBOM is signed and the signer identity equals to a given value.

If you have not created an SBOM yet, create an sbom attestation, for example:

```bash
valint bom ubuntu:latest -o attest
```

Edit policy parameters under ```attest.cocosign.policies.modules.input identity``` in the `signed-by.yml` file:

```yaml
identity:
  emails:
    - mikey@resilience-sec.com
```

Verify the attestation against the policy:

```bash
valint verify ubuntu:latest -i attest -c signed-by.yml
```

#### Blacklist Packages

This policy verifies that an SBOM does not include packages in the list of risky packages.

If you have not created an SBOM yet, create an sbom attestation, for example:

```bash
valint bom ubuntu:latest -o statement-cyclonedx-json
```

Edit the list of the risky licenses in the config object, within the rego code in file ```blacklist-packages.yml```:

```rego
config := {
  "blacklist": ["pkg:npm/readable-stream@1.0.34", "pkg:npm/trim@1.0.1"],
  "blacklisted_limit":0
}

```

Verify the attestation against the policy:

```bash
valint verify ubuntu:latest -i statement-cyclonedx-json -c blacklist-packages.yml
```

#### Required Packages

This policy verifies that the SBOM includes packages from the list of required packages.

If you have not created an SBOM yet, create an sbom attestation, for example:

```bash
valint bom ubuntu:latest -o statement-cyclonedx-json
```

Edit the list of the required packages in the config object, within the rego code in file ```required-packages.yml```:

```rego
config := {
  "required_pkgs": ["pkg:npm/readable-stream@1.0.34", "pkg:npm/trim@1.0.1"],
  "violations_limit":0
}
```

The policy checks if there is a package listed in SBOM whose name contains the name of a required package as a substring. For example, if the package name is ```pkg:deb/ubuntu/bash@5.1-6ubuntu1?arch=amd64\u0026distro=ubuntu-22.04```, it will match any substring, like just ```bash``` or ```bash@5.1-6ubuntu1```.

Verify the attestation against the policy:

```bash
valint verify ubuntu:latest -i statement-cyclonedx-json -c required-packages.yml
```

#### Banned licenses

This policy verifies that the SBOM does not include licenses in the list of risky licenses.

Create an sbom attestation, for example:

```bash
valint bom ubuntu:latest -o statement-cyclonedx-json
```

Edit the list of the risky licenses in the config object, within the rego code in file ```banned-licenses.yml```:

```rego
config := {
  "blacklist": {"GPL", "MPL"},
  "blacklisted_limit" : 200
}
```

Verify the attestation against the policy:

```bash
valint verify ubuntu:latest -i statement-cyclonedx-json -c banned-licenses.yml
```

#### Complete Licenses

This policy verifies that every package in the SBOM has a license.

If you have not created an SBOM yet, create an sbom attestation, for example:

```bash
valint bom ubuntu:latest -o statement-cyclonedx-json
```

Verify the attestation against the policy:

```bash
valint verify ubuntu:latest -i statement-cyclonedx-json -c complete-licenses.yml
```

#### Fresh SBOM

This policy verifies that the SBOM is not older than a given number of days.

If you have not created an SBOM yet, create an sbom attestation, for example:

```bash
valint bom ubuntu:latest -o statement-cyclonedx-json
```

Edit the policy in the config object, within the rego code in file ```fresh-sbom.rego```:

```rego
config := {
    "max_days" : 30
}
```

Verify the attestation against the policy:

```bash
valint verify ubuntu:latest -i statement-cyclonedx-json -c fresh-sbom.yml
```

### Images

#### Fresh Image

This policy verifies that the image is not older than a given number of days.

If you have not created an SBOM yet, create an sbom attestation, for example:

```bash
valint bom ubuntu:latest -o statement-cyclonedx-json
```

Edit the policy in the config object, within the rego code in file ```fresh-image.rego```:

```rego
config := {
    "max_days" : 183
}
```

Verify the attestation against the policy:

```bash
valint verify ubuntu:latest -i statement-cyclonedx-json -c fresh-image.yml
```

#### Large Image

This policy verifies that the image is not larger than a given size.

If you have not created an SBOM yet, create an sbom attestation, for example:

```bash
valint bom ubuntu:latest -o statement-cyclonedx-json
```

Edit the policy in the config object, within the rego code in file ```large-image.rego```:

```rego
config := {
    "max_size" : 100000000
}
```

Verify the attestation against the policy:

```bash
valint verify ubuntu:latest -i statement-cyclonedx-json -c large-image.yml
```

### Git

#### No Commits To Main

This policy verifies that evidence has no commits made to main branch.

If you have not created an evidence yet, create one, for example:

```bash
valint bom git:https://github.com/golang/go -o statement
```

To verify the evidence against the policy:

```bash
valint verify git:https://github.com/golang/go -i statement -c no-commit-to-main.yml
```

### SLSA

#### Builder name

This policy verifies that the builder name of the SLSA statement equals to a given value.

If you have not created an SLSA statement yet, create an SLSA statement, for example:

```bash
valint slsa ubuntu:latest -o statement
```

Edit policy parametersin `rego` code in the `builder.yml` file:

```rego
config := {
  "builderType": "local",
  "hostname": "builder1"
}
```

Verify the attestation against the policy:

```bash
valint verify ubuntu:latest -i statement-slsa -c builder.yml
```

### Sarif Reports

#### Generic SARIF Policy

This policy allows to verify any SARIF report against a given policy. The policy has several parameters to check against:

* ruleLevel: the level of the rule, can be "error", "warning", "note", "none"
* ruleIds: the list of the rule IDs to check against
* precision: the precision of the check, can be "exact", "substring", "regex"
* ignore: the list of the rule IDs to ignore
* maxAllowed: the maximum number of violations allowed

These values can be changed in the `config` section in the `generic-sarif.rego` file.

Create a trivy sarif report of the vulnerabilities of an image:

```bash
trivy image ubuntu:latest -f sarif -o ubuntu-cve.json
```

Create an evidence from this report:

```bash
valint bom ubuntu-cve.json --predicate-type http://scribesecurity.com/evidence/generic/v0.1  -o statement-generic
```

Verify the attestation against the policy:

```bash
valint verify ubuntu-cve.json -i statement-generic -c generic-sarif.yml
```

##### No Critical CVEs

To verify that the SARIF report does not contain any critical CVEs, set the following parameters in the `config` section in the `generic-sarif.rego` file:

```rego
config := {
   "ruleLevel": ["critical"],
   "precision": [],
   "ruleIDs": [],
   "ignore": [],
   "maxAllowed": 0
}
```

##### Limit High CVEs

To verify that the SARIF report does not contain more than 10 high CVEs, set the following parameters in the `config` section in the `generic-sarif.rego` file:

```rego
config := {
   "ruleLevel": ["high"],
   "precision": [],
   "ruleIDs": [],
   "ignore": [],
   "maxAllowed": 10
}
```

##### Do Not Allow Specific CVEs

To verify that the SARIF report does not contain CVE-2021-1234 and CVE-2021-5678, set the following parameters in the `config` section in the `generic-sarif.rego` file:

```rego
config := {
   "ruleLevel": [],
   "precision": [],
   "ruleIDs": ["CVE-2021-1234", "CVE-2021-5678"],
   "ignore": [],
   "maxAllowed": 0
}
```

## Writing Policy Files

The rego policies can be written either as snippets in the yml file, or as separate rego files. The advantage of using separate rego files is that one can enjoy the IDE support for rego, such as syntax highlighting and linting, and one can test the rego code more easily.

An example of such a rego file is give in the ```generic-sarif.rego``` file, that is consumed by the ```generic-sarif.yml``` configuraion file. To evaluate the policy:

```bash
valint verify ubuntu-cve.json -i statement-generic -c generic-sarif.yml
```

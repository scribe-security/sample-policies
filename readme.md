# Sample Policies

This repo includes samples of policy configuraions for Scribe's ```valint``` tool.

## Preparation

1. Install `valint`:

    ```bash
    curl -sSfL https://get.scribesecurity.com/install.sh  | sh -s -- -t valint
    ```

2. Clone this repo.

3. In order to run a policy, its rego file shold be referred by a valint config. Each `.yaml` represents such a config and is ready for use, but one should either replace rego path with and actual one or run `valint` from this repo's root directory.

## Policy Catalogue

Each implemented policy in the table that has an example in this repo has a link to the policy description.

| Policy | Description | Additional Info |
| --- | --- | --- |
| [Forbid Unsigned Artifacts](#forbid-unsigned-artifacts) | Verify the artifact's authenticity and signer identity. | [SBOM](#sboms) |
| [Blocklist Packages](#blocklist-packages) | Prevent risky packages in the artifact. | [SBOM](#sboms) |
| [Required Packages](#required-packages) | Ensure mandatory packages/files in the artifact. | [SBOM](#sboms) |
| [Banned Licenses](#banned-licenses) | Restrict inclusion of certain licenses in the artifact. | [SBOM](#sboms) |
| [Complete Licenses](#complete-licenses) | Guarantee all packages have valid licenses. | [SBOM](#sboms) |
| [Fresh Artifact](#fresh-artifact) | Verify an artifact's freshness. | [SBOM](#sboms) |
| [Fresh Image](#fresh-image) | Ensure an image freshness. | [Image SBOM](#images) |
| [Restrict Shell Image Entrypoint](#restrict-shell-image-entrypoint) | Prevent shell as image entrypoint. | [SBOM](#sboms) |
| [Blocklist Image Build Scripts](#blocklist-image-build-scripts) | Restrict build scripts in image build. | [Image SBOM](#images) |
| [Verify Image Lables/Annotations](#verify-image-lablesannotations) | Ensure image has required labels (e.g., git-commit). | [SBOM](#sboms)  |
| [Forbid Huge Images](#forbid-large-images) | Limit image size. | [Image SBOM](#images) |
| [Coding Permissions](#coding-permissions) | Control file modifications by authorized identities. | [Git SBOM](#git) |
| Merging Permissions | Ensure authorized identities merge to main. | Counterpart to [Forbid Commits To Main](#forbid-commits-to-main)? |
| [Forbid Unsigned Commits](#forbid-unsigned-commits) | Prevent unsigned commits in evidence. | [Git SBOM](#git) |
| [Forbid Commits To Main](#forbid-commits-to-main) | Verify there were no commits to the main branch. | [Git SBOM](#git) |
| [Verify Use of Specific Builder](#builder-name) | Enforce use of a specific builder for artifact. | [SLSA-Prov](#slsa) |
| [Banned Builder Dependencies](#banned-builder-dependencies) | Restrict banned builder dependencies. | [SLSA-Prov](#slsa) |
| [Verify Build Time](#build-time) | Validate build time within window. | [SLSA-Prov](#slsa) |
| [Verify Byproducts Produced](#produced-byproducts) | Ensure that specific byproducts are produced. | [SLSA-Prov](#slsa) |
| [Verify That Field Exists](#verify-that-field-exists) | Ensure that specific field exists in the SLSA statement. | [SLSA-Prov](#slsa) |
| [No Critical CVEs](#no-critical-cves) | Prohibit ANY critical CVEs. | [SARIF](#sarif-reports) |
| [Limit High CVEs](#limit-high-cves) | Limit high CVEs. | [SARIF](#sarif-reports) |
| [Do Not Allow Specific CVEs](#do-not-allow-specific-cves) | Prevent specific CVEs in the artifact. | [SARIF](#sarif-reports) |
| [No Static Analysis Errors](#no-static-analysis-errors) | Prevent static analysis errors in the artifact. | [SARIF](#sarif-reports) |
| [Limit Static Analysis Warnings](#limit-static-analysis-warnings) | Restrict static analysis warnings count. | [SARIF](#sarif-reports) |
| [Do Not Allow Specific Static Analysis Rules](#do-not-allow-specific-static-analysis-rules) | Restrict specific static analysis warnings. | [SARIF](#sarif-reports) |
| [Do Not Allow Vulnerabilities Based On Specific Attack Vector](#do-not-allow-vulnerabilities-based-on-specific-attack-vector) | Restrict vulnerabilities based on specific attack vector. | [SARIF](#sarif-reports) |
| [Report IaC Configuration errors](#report-iac-configuration-errors) | Check if there are any IaC configuration errors. | [SARIF](#sarif-reports) |
| [Verify Semgrep SARIF report](#verify-semgrep-sarif-report) | Check for specific violations in a semgrep report. | [SARIF](#sarif-reports) |
| [Forbid Accessing Host](#forbid-accessing-host) | Do not allow images with detected vulnerabilities giving access to the host system. | Generic Evidence | [Generic](#generic) |
| No Package Downgrading | Restrict package downgrades. | src and dst [SBOM](#sboms) |
| No License Modification | Prevent license modifications. | src and dst [SBOM](#sboms) |
| Verify Source code Integrity | Verify that the artifact source code has not been modified | src and dst [Git SBOM](#git) |
| Verify Dependencies Integrity | Verify that specific files or folders have not been modified | src and dst [SBOM](#sboms) |
| [Verify Github Branch Protection](policies/apis/github-branch-protection.md) | Verify that the branch protection rules are compliant to required | None |
| [Verify GitLab Push Rules](policies/apis/gitlab-push-rules.md) | Verify that the push rules are compliant to required. GitLabs push rules overlap some of GitHub's branch protection rules | None |
### General Information

Most of the policies in this repo consist of two files: a `.yaml` and a `.rego`.

The first is a part of `valint` configuration file and needs to be merged to the actual `valint.yaml` or used separately if default `valint` config is sufficient.
The second is a rego file that contains the actual policy code. It can be used as is or merged to the `.yaml` file by quoting its content under `rego.script` parameter instead of using the `rego.file` one.

### SBOMs

An example of creating an SBOM evidence:

```bash
valint bom ubuntu:latest -o statement-cyclonedx-json
```

To verify the evidence against the policy call:

```bash
valint verify ubuntu:latest -i statement-cyclonedx-json -c <policyname>.yaml
```

An example of creating signed SBOM attestation:

```bash
valint bom ubuntu:latest -o attest
```

To verify the attestation against the policy call:

```bash
valint verify ubuntu:latest -i attest -c <policyname>.yaml
```

#### Forbid Unsigned Artifacts

This policy ([artifact-signed.yaml](policies/sboms/artifact-signed.yaml)) verifies that the SBOM is signed and the signer identity equals to a given value.

If you have not created an SBOM yet, create an sbom attestation, for example:

In [artifact-signed.yaml](policies/sboms/artifact-signed.yaml) file,
edit policy parameters ```attest.cocosign.policies.rules.input identity``` to reflect the expected signers identity.

You can also edit `target_type` to refelct the artifact type.

> Optional target types are `git`,`directory`, `image`, `file`, `generic`.

```yaml
evidence:
   target_type: image
with:
   identity:
      emails:
         - example@company.com
```

#### Blocklist Packages

This policy ([blocklist-packages.yaml](policies/sboms/blocklist-packages.yaml), [blocklist-packages.rego](policies/sboms/blocklist-packages.rego)) verifies an SBOM does not include packages in the list of risky packages.

`rego` code for this policy can be found in the [blocklist-packages.rego](policies/sboms/blocklist-packages.rego) file.

Edit the list of the risky licenses in the `input.rego.args` parameter in file [blocklist-packages.yaml](policies/sboms/blocklist-packages.yaml):

```yaml
with:
   blocklist:
      - "pkg:deb/ubuntu/tar@1.34+dfsg-1ubuntu0.1.22.04.1?arch=arm64&distro=ubuntu-22.04"
      - "log4j"
   blocklisted_limit: 0
```

#### Required Packages

This policy ([required-packages.yaml](policies/sboms/required-packages.yaml), [required-packages.rego](policies/sboms/required-packages.rego)) verifies that the SBOM includes packages from the list of required packages.

Edit the list of the required packages in the `input.rego.args` parameter in file [required-packages.yaml](policies/sboms/required-packages.yaml):

```yaml
with:
   required_pkgs:
      - "pkg:deb/ubuntu/bash@5.1-6ubuntu1?arch=amd64\u0026distro=ubuntu-22.04"
   violations_limit: 1
```

The policy checks if there is a package listed in SBOM whose name contains the name of a required package as a substring. For example, if the package name is ```pkg:deb/ubuntu/bash@5.1-6ubuntu1?arch=amd64\u0026distro=ubuntu-22.04```, it will match any substring, like just ```bash``` or ```bash@5.1-6ubuntu1```.

#### Banned Licenses

This policy ([banned-licenses.yaml](policies/sboms/banned-licenses.yaml), [banned-licenses.rego](policies/sboms/banned-licenses.rego)) verifies that the SBOM does not include licenses from the list of risky licenses.

Edit the list of the risky licenses in the `input.rego.args` parameter in file [banned-licenses.yaml](policies/sboms/banned-licenses.yaml):

```yaml
rgs:
   blocklist:
      - GPL
      - MPL
   blocklisted_limit : 10
```

#### Complete Licenses

This policy ([complete-licenses.yaml](policies/sboms/complete-licenses.yaml), [complete-licenses.rego](policies/sboms/complete-licenses.rego)) verifies that every package in the SBOM has a license.

It doesn't have any additional parameters.

#### Fresh Artifact

This policy ([fresh-sbom.yaml](policies/sboms/fresh-sbom.yaml), [fresh-sbom.rego](policies/sboms/fresh-sbom.rego)) verifies that the SBOM is not older than a given number of days.

Edit the policy in the `input.rego.args` parameter in file [fresh-sbom.yaml](policies/sboms/fresh-sbom.yaml):

```yaml
with:
   max_days : 30
```

### Images

An example of creating an evidence:

```bash
valint bom ubuntu:latest -o statement
```

To verify the evidence against the policy:

```bash
valint verify ubuntu:latest -i statement -c <policyname>.yaml
```

#### Restrict Shell Image Entrypoint

This policy ([restrict-shell-entrypoint.yaml](policies/images/restrict-shell-entrypoint.yaml), [restrict-shell-entrypoint.rego](policies/images/restrict-shell-entrypoint.rego)) verifies that the image entrypoint does not provide shell access by default. It does so by verifying that both `Entrypoint` and `Cmd` don't contain `sh` (there's an exclusion for `.sh` though).

This policy is not configurable.

#### Blocklist Image Build Scripts

This policy ([blocklist-build-scripts.yaml](policies/images/blocklist-build-scripts.yaml), [blocklist-build-scripts.rego](policies/images/blocklist-build-scripts.rego)) verifies that the image did not run blocklisted scripts on build.

Edit the list of the blocklisted scripts in the `input.rego.args` parameter in file [blocklist-build-scripts.yaml](policies/images/no-build-scripts.yaml):

```yaml
with:
   blocklist:
      - curl
```

#### Verify Image Lables/Annotations

This policy ([verify-labels.yaml](policies/images/verify-labels.yaml), [verify-labels.rego](policies/images/verify-labels.rego)) verifies that image has labels with required values.

Edit the list of the required labels in the config object in file [verify-labels.yaml](policies/images/verify-labels.yaml):

```yaml
with:
   labels:
      - label: "org.opencontainers.image.version"
        value: "22.04"
```

#### Fresh Image

This policy ([fresh-image.yaml](policies/images/fresh-image.yaml), [fresh-image.rego](policies/images/fresh-image.rego)) verifies that the image is not older than a given number of days.

Edit the policy in the `input.rego.args` parameter in file [fresh-image.yaml](policies/images/fresh-image.yaml):

```yaml
with:
   max_days: 183
```

#### Forbid Large Images

This policy ([forbid-large-images.yaml](policies/images/forbid-large-images.yaml), [forbid-large-images.rego](policies/images/forbid-large-images.rego)) verifies that the image is not larger than a given size.

Set max size in bytes in the `input.rego.args` parameter in file [forbid-large-images.yaml](policies/images/forbid-large-images.yaml):

```yaml
with:
   max_size: 77808811
```

### Git

An example of creating a Git evidence:

```bash
valint bom git:https://github.com/golang/go -o statement
```

To verify the evidence against the policy:

```bash
valint verify git:https://github.com/golang/go -i statement -c <policyname>.yaml
```

#### Coding Permissions

This policy ([coding-permissions.yaml](policies/git/coding-permissions.yaml), [coding-permissions.rego](policies/git/coding-permissions.rego)) verifies that files from the specified list were modified by authorized users only.

For this policy be able to run, the evidence must include a reference to the files that were modified in the commit. This can be done by adding parameter `--components commits,files` to the `valint bom` command.

For specifying the list of files and identities, edit the `input.rego.args` parameter in file [coding-permissions.yaml](policies/git/coding-permissions.yaml).
This example for repository [Golang Build](https://github.com/golang/build) verifies that files `build.go` and `internal/https/README.md` were modified only by identities containing `@golang.com` and `@golang.org`:

```yaml
with:
   ids:
      - "@golang.com"
      - "@golang.org"
   files:
      - "a.txt"
      - "somedir/b.txt"
```

#### Forbid Unsigned Commits

This policy ([no-unsigned-commits.yaml](policies/git/no-unsigned-commits.yaml), [no-unsigned-commits.rego](policies/git/no-unsigned-commits.rego)) verifies that evidence has no unsigned commits. It does not verify the signatures though.

#### Forbid Commits To Main

This policy ([no-commit-to-main.yaml](policies/git/no-commit-to-main.yaml), [no-commit-to-main.rego](policies/git/no-commit-to-main.rego)) verifies that evidence has no commits made to main branch.

### SLSA

Example of creating a SLSA statement:

```bash
valint slsa ubuntu:latest -o statement
```

Example of verifying a SLSA statement:

```bash
valint verify ubuntu:latest -i statement-slsa -c <policyname>.yaml
```

#### Builder Name

This policy ([verify-builder.yaml](policies/slsa/verify-builder.yaml), [verify-builder.rego](policies/slsa/verify-builder.rego)) verifies that the builder name of the SLSA statement equals to a given value.

Edit policy parameters in the `input.rego.args` parameter in file [verify-builder.yaml](policies/slsa/verify-builder.yaml):

```yaml
with:
   id: "local"
```

#### Banned Builder Dependencies

This policy ([banned-builder-deps.yaml](policies/slsa/banned-builder-deps.yaml), [banned-builder-deps.rego](policies/slsa/banned-builder-deps.rego)) verifies that the builder used to build an artifact does not have banned dependencies (such as an old openSSL version).

Edit policy parameters in the `input.rego.args` parameter in file [banned-builder-deps.yaml](policies/slsa/banned-builder-deps.yaml):

```yaml
with:
   blocklist:
      - name: "valint"
         version: "0.0.0"
```

#### Build Time

This policy ([build-time.yaml](policies/slsa/build-time.yaml), [build-time.rego](policies/slsa/build-time.rego)) verifies that the build time of the SLSA statement is within a given time window The timezone is derived from the timestamp in the statement.

Edit policy parameters in the `input.rego.args` parameter in file [build-time.yaml](policies/slsa/build-time.yaml):

```yaml
with:
   start_hour: 8
   end_hour: 20
   workdays:
      - "Sunday"
      - "Monday"
      - "Tuesday"
      - "Wednesday"
      - "Thursday"
```

#### Produced Byproducts

This policy ([verify-byproducts.yaml](policies/slsa/verify-byproducts.yaml), [verify-byproducts.rego](policies/slsa/verify-byproducts.rego)) verifies that the SLSA statement contains all the required byproducts.
According to the SLSA Provenance [documentation](https://slsa.dev/spec/v1.0/provenance), there are no mandatory fields in the description of a byproduct, but at least one of `uri, digest, content` should be specified.
So, the policy checks if each byproduct specified in the policy configuration is present in one of those fields of any byproduct in the SLSA statement. It does so by calling the `contains` function, so the match is not exact.

Before running the policy, specify desired byproducts in the `input.rego.args` parameter in file [verify-byproducts.yaml](policies/slsa/verify-byproducts.yaml):

```yaml
with:
   byproducts:
      - 4693057ce2364720d39e57e85a5b8e0bd9ac3573716237736d6470ec5b7b7230
```

#### Verify That Field Exists

This policy ([field-exists.yaml](policies/slsa/field-exists.yaml), [field-exists.rego](policies/slsa/field-exists.rego)) verifies that the SLSA statement contains a field with the given path.

Before running the policy, specify desired paths in the `input.rego.args` parameter in file [field-exists.yaml](policies/slsa/field-exists.yaml):

```yaml
with:
   paths:
      - "predicate/runDetails/builder/builderDependencies"
   violations_threshold: 0
```

### Sarif Reports

#### Generic SARIF Policy

This policy ([verify-sarif.yaml](policies/sarif/verify-sarif.yaml), [verify-sarif.rego](policies/sarif/verify-sarif.rego)) allows to verify any SARIF report against a given policy. The policy has several parameters to check against:

* ruleLevel: the level of the rule, can be "error", "warning", "note", "none"
* ruleIds: the list of the rule IDs to check against
* precision: the precision of the check, can be "exact", "substring", "regex"
* ignore: the list of the rule IDs to ignore
* maxAllowed: the maximum number of violations allowed

These values can be changed in the `input.rego.args` section in the [verify-sarif.yaml](policies/sarif/verify-sarif.yaml) file.

##### Creating a BOM out of a SARIF report

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
valint verify ubuntu-cve.json -i statement-generic -c policies/sarif/verify-sarif.yaml
```

###### Running Trivy On Docker Container Rootfs

As an alternative, one can run `trivy` against an existing Docker container rootfs:

```bash
docker run --rm -it alpine:3.11
```

Then, inside docker run:

```bash
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
trivy rootfs / -f sarif -o rootfs.json
```

Then, outside docker run this to copy the report from the container:

```bash
docker cp $(docker ps -lq):/rootfs.json .
```

After that create the evidence and verify it as described above.

##### No Critical CVEs

To verify that the SARIF report does not contain any critical CVEs, set the following parameters in the `rego.args` section in the[verify-sarif.yaml](policies/sarif/verify-sarif.yaml) file:

```yaml
with:
   rule_level:
      - critical
   precision: []
   rule_ids: []
   ignore: []
   max_allowed: 0
```

##### Limit High CVEs

To verify that the SARIF report does not contain more than specified number of CVEs with high level (let's say 10), set the following parameters in the `rego.args` section in the[verify-sarif.yaml](policies/sarif/verify-sarif.yaml) file:

```yaml
with:
   rule_level: high,
   precision: []
   rule_ids: []
   ignore: []
   max_allowed: 10
```

##### Do Not Allow Specific CVEs

To verify that the SARIF report does not contain certain CVEs (let's say CVE-2021-1234 and CVE-2021-5678), set the following parameters in the `rego.args` section in the[verify-sarif.yaml](policies/sarif/verify-sarif.yaml) file:

```yaml
with:
   rule_level:
      - "error"
      - "warning"
      - "note"
      - "none"
   precision: []
   rule_ids:
      - "CVE-2021-1234"
      - "CVE-2021-5678"
   ignore: []
   max_allowed: 0
```

##### No Static Analysis Errors

To verify that the SARIF report does not contain any static analysis errors, set the following parameters in the `rego.args` section in the[verify-sarif.yaml](policies/sarif/verify-sarif.yaml) file:

```yaml
with:
   rule_level:
      - "error"
   precision: []
   rule_ids: []
   ignore: []
   max_allowed: 0
```

##### Limit Static Analysis Warnings

To verify that the SARIF report does not contain more than specified number of static analysis warnings (let's say 10), set the following parameters in the `rego.args` section in the[verify-sarif.yaml](policies/sarif/verify-sarif.yaml) file:

```yaml
with:
   rule_level:
      - "warning"
   precision: []
   rule_ids: []
   ignore: []
   max_allowed: 10
```

##### Do Not Allow Specific Static Analysis Rules

To verify that the SARIF report does not contain static analysis warnings from the following rules: "rule1", "rule2", "rule3", set the following parameters in the `rego.args` section in the[verify-sarif.yaml](policies/sarif/verify-sarif.yaml) file:

```yaml
with:
   rule_level:
      - "error"
      - "warning"
      - "note"
      - "none"
   precision: []
   rule_ids:
      - "rule1"
      - "rule2"
      - "rule3"
   ignore: []
   max_allowed: 0
```

##### Do Not Allow Vulnerabilities Based On Specific Attack Vector

Trivy/grype reports usually contain descriptions for some CVEs, like impact and attack vector.
This policy ([verify-attack-vector.yaml](policies/sarif/verify-attack-vector.yaml), [verify-attack-vector.rego](policies/sarif/verify-attack-vector.rego)) is meant to restrict number of vulnerabilities with specific attack vectors.
For example, to restrict vulnerabilities with attack vector "stack buffer overflow", set the following parameters in the `rego.args` section in the [verify-attack-vector.yaml](policies/sarif/verify-attack-vector.yaml) file:

```yaml
with:
   attack_vectors:
      - "stack buffer overflow"
   violations_threshold: 0
```

Then run the policy against the SARIF report as described above.

#### Report IaC Configuration errors

This policy ([report-iac-errors.yaml](policies/sarif/report-iac-errors.yaml), [report-iac-errors.rego](policies/sarif/report-iac-errors.rego)) allows to verify a Trivy IaC report and check if there are any errors in the configuration.

First, create a trivy report of the misconfigurations of a Dockerfile:

```bash
trivy config <dir_containing_dockerfile> -f sarif -o my-image-dockerfile.json
```

Create an evidence from this report:

```bash
valint bom my-image-dockerfile.json --predicate-type http://scribesecurity.com/evidence/generic/v0.1  -o statement-generic
```

Verify the attestation against the policy:

```bash
valint verify my-image-dockerfile.json -i statement-generic -c policies/sarif/report-iac-errors.yaml
```

The only configurable parameter in [report-iac-errors.yaml](policies/sarif/report-iac-errors.yaml) is `violations_threshold`, which is the maximum number of errors allowed in the report:

```yaml
with:
   violations_threshold: 0
```

#### Verify Semgrep SARIF report

`semgrep`, a code analysis tool, can produce SARIF reports, which later can be verified by `valint` against a given policy.

This policy ([verify-semgrep-report.yaml](policies/sarif/verify-semgrep-report.yaml), [verify-semgrep-report.rego](policies/sarif/verify-semgrep-report.rego)) allows to verify that given SARIF report does not contain specific rules violations.

First, one needs to create a semgrep report (say, for the `openvpn` repo):

```bash
cd openvpn/
semgrep scan --config auto -o semgrep-report.sarif --sarif
```

Then, create an evidence from this report:

```bash
valint bom semgrep-report.sarif --predicate-type http://scribesecurity.com/evidence/generic/v0.1  -o statement-generic
```

Configuration of this policy is done in the file [verify-semgrep-report.yaml](policies/sarif/verify-semgrep-report.yaml). In this example we forbid any violations of the `use-after-free` rule:

```yaml
with:
   rule_ids:
      - "use-after-free"
   violations_threshold: 0
```

Then, run `valint verify` as usual:

```bash
valint verify semgrep-report.sarif -i statement-generic -c policies/sarif/verify-semgrep-report.yaml
```

If any violations found, the output will contain their description, including the violated rule and the file where the violation was found.

### Forbid Accessing Host

Trivy k8s analysis can highlight some misconfigurations which allow container to access host filesystem or network. The goal of this policy is to detect such misconfigurations.

To run this policy one has to create a Trivy k8s report and create a generic statement with `valint` from it. Then, simply run the policy against this statement. No additional configuration required.

## Writing Policy Files

The rego policies can be written either as snippets in the yaml file, or as separate rego files. The advantage of using separate rego files is that one can enjoy the IDE support for rego, such as syntax highlighting and linting, and one can test the rego code more easily.

An example of such a rego file is give in the [verify-sarif.rego](policies/sarif/verify-sarif.rego) file, that is consumed by the [verify-sarif.yaml](policies/sarif/verify-sarif.yaml) configuraion file. To evaluate the policy:

```bash
valint verify ubuntu-cve.json -i statement-generic -c verify-sarif.yaml
```

# GitHub Branch Protection Verification

Valint policies can be used to verify settings via APIs. This document explains how to use Valint to verify GitHub branch protection settings.

To verify run the following command:
```bash
valint verify -c policies/apis/gith-branch-protection.yml --policy-args Owner=scribe-security --policy-args Repo=scribe2 --policy-args Branch=main --policy-args Token=$GH_TOKEN
```

Notes:
- GH_TOKEN is a GitHub personal access token.
- Although the policy does not consume any attestations, there should exist at least one attestation in the attestation store.


Here is an example of the policy configuration file, followed by a description of the parameters.
```yaml
attest:
  cocosign:
    policies:
    - name: github-branch-protection
      enable: true
      modules:
      - name: github-branch-protection
        type: verify-artifact
        enable: true
        input:
          signed: false
          rego:
            args:
              api_token: '{{ .Args.Token }}'
              owner: '{{ .Args.Owner }}'
              repo: '{{ .Args.Repo }}'
              branch: '{{ .Args.Branch }}'
              branch_protection_rules:
                required_pull_request_reviews.dismiss_stale_reviews: true
                required_pull_request_reviews.require_code_owner_reviews: false
                required_pull_request_reviews.require_last_push_approval: false
                required_pull_request_reviews.required_approving_review_count: 1
                required_pull_request_reviews.bypass_pull_request_allowances.users: []
                required_pull_request_reviews.bypass_pull_request_allowances.teams: []
                required_pull_request_reviews.bypass_pull_request_allowances.apps: []
                required_pull_request_reviews.dismissal_restrictions.users: []
                required_pull_request_reviews.dismissal_restrictions.teams: []
                required_pull_request_reviews.dismissal_restrictions.apps: []

                required_status_checks.checks: []
                required_status_checks.strict: false
                required_status_checks.contexts: []

                restrictions.users: []
                restrictions.teams: []
                restrictions.apps: []

                required_signatures: false
                enforce_admins: false
                required_linear_history: false
                allow_force_pushes: false
                allow_deletions: true
                block_creations: false
                required_conversation_resolution: false
                lock_branch: false
                allow_fork_syncing: false
            path: github-branch-protection.rego
```


## Branch Protection Rule Parameters

### `required_pull_request_reviews.dismiss_stale_reviews`
- **Description:** Automatically dismisses approved reviews when new commits are pushed.
- **Recommended Setting:** `true` - Ensures pull requests are always re-reviewed after new changes.

### `required_pull_request_reviews.require_code_owner_reviews`
- **Description:** Requires review from designated code owners before merging.
- **Recommended Setting:** `true` - Adds an additional layer of scrutiny from experts.

### `required_pull_request_reviews.require_last_push_approval`
- **Description:** Requires approval from the last person who pushed to the branch.
- **Recommended Setting:** `true` - Guarantees the final pusher's approval, ensuring the latest changes are reviewed.

### `required_pull_request_reviews.required_approving_review_count`
- **Description:** The number of required approving reviews before merging.
- **Recommended Setting:** `2` or more - Promotes comprehensive review by multiple team members.

### `required_pull_request_reviews.bypass_pull_request_allowances`
- **Subcategories:** `users`, `teams`, `apps`
- **Description:** Specifies which users, teams, or apps can bypass pull request requirements.
- **Recommended Setting:** Minimize or avoid bypass allowances to maintain strict review processes.

### `required_pull_request_reviews.dismissal_restrictions`
- **Subcategories:** `users`, `teams`, `apps`
- **Description:** Specifies who can dismiss pull request reviews.
- **Recommended Setting:** Restrict dismissal capabilities to maintain the integrity of reviews.

### `required_status_checks`
- **Subcategories:** `checks`, `strict`, `contexts`
- **Description:** Enforces certain checks before a pull request can be merged.
- **Recommended Setting:** 
    - `strict`: `true` - Enforces all configured checks to pass before merging.
    - `contexts`: Specify important status checks that must pass.

### `restrictions`
- **Subcategories:** `users`, `teams`, `apps`
- **Description:** Limits who can push to the protected branch.
- **Recommended Setting:** Restrict to a minimal set of responsible individuals or teams.

### `required_signatures`
- **Description:** Requires all commits to be signed.
- **Recommended Setting:** `true` - Ensures commit authenticity.

### `enforce_admins`
- **Description:** Applies the same rules to administrators.
- **Recommended Setting:** `true` - Enforces rules uniformly, even for admins.

### `required_linear_history`
- **Description:** Requires a linear commit history.
- **Recommended Setting:** `true` - Maintains a straightforward and clean history.

### `allow_force_pushes`
- **Description:** Permits force pushes to the branch.
- **Recommended Setting:** `false` - Preserves historical integrity.

### `allow_deletions`
- **Description:** Allows deletion of the branch.
- **Recommended Setting:** `false` - Protects key branches from removal.

### `block_creations`
- **Description:** Prevents the creation of new branches.
- **Recommended Setting:** `true` - Limits branch proliferation.

### `required_conversation_resolution`
- **Description:** Requires resolution of all conversations before merging.
- **Recommended Setting:** `true` - Ensures all discussions are addressed.

### `lock_branch`
- **Description:** Prevents further changes to the branch.
- **Recommended Setting:** `true` - Useful for archiving or finalizing branches.

### `allow_fork_syncing`
- **Description:** Allows fork syncing with the protected branch.
- **Recommended Setting:** `false` - Limits potential unauthorized changes.


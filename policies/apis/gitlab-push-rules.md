# GitLab Push Rules Verification

Valint policies can be used to verify settings via APIs. This document explains how to use Valint to verify GitHub branch protection settings.

To verify run the following command:
```bash
valint verify -c policies/apis/gitlab-push-rules.yml --policy-args Project=12345678 --policy-args Token=$GL_TOKEN
```

Notes:
- GL_TOKEN is a Gitlab access token. It should be crated with Maintainer role and api_read scope.
- Although the policy does not consume any attestations, there should exist at least one attestation in the attestation store.



This document outlines the GitLab push rule parameters for configuring repository push rules. Each parameter is described along with its type, requirement status, and a brief description. Recommendations for more secure settings are also provided.

## Push Rule Parameters

### `author_email_regex`
- **Description:** All commit author emails must match this regex, e.g., `@my-company.com$`.
- **Recommended Setting:** Use a regex pattern matching your organization's email domain to ensure commits are made by authorized personnel.

### `branch_name_regex`
- **Description:** All branch names must match this regex, e.g., `(feature|hotfix)/*`.
- **Recommended Setting:** Enforce a naming convention for branches to aid in organization and consistency.

### `commit_committer_check`
- **Description:** Users can only push commits if the committer email is one of their own verified emails.
- **Recommended Setting:** `true` - Ensures that the committer is a verified user, enhancing security.

### `commit_committer_name_check`
- **Description:** Users can only push commits if the commit author name is consistent with their GitLab account name.
- **Recommended Setting:** `true` - Verifies the identity of the person making the commit.

### `commit_message_negative_regex`
- **Description:** No commit message is allowed to match this regex, e.g., `ssh://`.
- **Recommended Setting:** Define a pattern to block commit messages containing specific undesired content or formats.

### `commit_message_regex`
- **Description:** All commit messages must match this regex, e.g., `Fixed \d+\..*`.
- **Recommended Setting:** Use a regex pattern to enforce a specific format for commit messages, aiding clarity and tracking.

### `deny_delete_tag`
- **Description:** Deny deleting a tag.
- **Recommended Setting:** `true` - Prevents accidental or unauthorized deletion of tags.

### `file_name_regex`
- **Description:** All committed file names must not match this regex, e.g., `(jar|exe)$`.
- **Recommended Setting:** Set a pattern to restrict committing files of certain types or naming conventions, enhancing security.

### `max_file_size`
- **Description:** Maximum file size (MB) allowed for push.
- **Recommended Setting:** Set a reasonable size limit to prevent overly large files from being committed.

### `member_check`
- **Description:** Restrict commits by author (email) to existing GitLab users.
- **Recommended Setting:** `true` - Restricts commits to verified members, improving security.

### `prevent_secrets`
- **Description:** GitLab rejects any files that are likely to contain secrets.
- **Recommended Setting:** `true` - Helps in preventing sensitive data exposure in the repository.

### `reject_unsigned_commits`
- **Description:** Rejects commits not signed through GPG.
- **Recommended Setting:** `true` - Ensures authenticity and integrity of commits.

---

Adjust these settings as necessary to fit the specific needs of your project and team, balancing security with practicality.

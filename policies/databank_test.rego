# Tests for the databank access policy.
#
# Run with:  docker compose run --rm opa test /policies -v
#
# Every test names the user, the dataset and the expected outcome, so the file
# doubles as the written access-control matrix.
package databank_test

import rego.v1

import data.databank

# --- users -------------------------------------------------------------------

alice := {"institution": "UniversityA", "roles": ["researcher"]}

arun := {"institution": "UniversityA", "roles": ["data_steward"]}

bob := {"institution": "LabB", "roles": ["researcher"]}

priya := {"institution": "LabB", "roles": ["admin"]}

# A user whose token carries no institution and no roles.
eve := {"institution": "", "roles": []}

# --- datasets ----------------------------------------------------------------

ua_public := {"owner_institution": "UniversityA", "sensitivity": "public", "shared_with": []}

ua_internal_shared := {"owner_institution": "UniversityA", "sensitivity": "internal", "shared_with": ["LabB"]}

ua_restricted := {"owner_institution": "UniversityA", "sensitivity": "restricted", "shared_with": []}

ua_restricted_shared := {"owner_institution": "UniversityA", "sensitivity": "restricted", "shared_with": ["LabB"]}

labb_restricted := {"owner_institution": "LabB", "sensitivity": "restricted", "shared_with": ["UniversityA"]}

# --- public data -------------------------------------------------------------

test_anyone_reads_public if {
	databank.allow with input as {"user": bob, "action": "read_metadata", "dataset": ua_public}
}

test_anyone_downloads_public if {
	databank.allow with input as {"user": bob, "action": "download", "dataset": ua_public}
}

# --- own institution ---------------------------------------------------------

test_owner_downloads_internal if {
	databank.allow with input as {"user": alice, "action": "download", "dataset": ua_internal_shared}
}

test_owner_reads_restricted_metadata if {
	databank.allow with input as {"user": alice, "action": "read_metadata", "dataset": ua_restricted}
}

# The headline rule: same dataset, same institution, different role.
test_researcher_cannot_download_restricted if {
	not databank.allow with input as {"user": alice, "action": "download", "dataset": ua_restricted}
}

test_steward_can_download_restricted if {
	databank.allow with input as {"user": arun, "action": "download", "dataset": ua_restricted}
}

test_admin_can_download_own_restricted if {
	databank.allow with input as {"user": priya, "action": "download", "dataset": labb_restricted}
}

# --- sharing -----------------------------------------------------------------

test_shared_institution_reads_metadata if {
	databank.allow with input as {"user": bob, "action": "read_metadata", "dataset": ua_restricted_shared}
}

test_shared_institution_cannot_download if {
	not databank.allow with input as {"user": bob, "action": "download", "dataset": ua_restricted_shared}
}

test_shared_institution_cannot_download_internal if {
	not databank.allow with input as {"user": bob, "action": "download", "dataset": ua_internal_shared}
}

# --- other institutions ------------------------------------------------------

test_outsider_cannot_read_unshared_restricted if {
	not databank.allow with input as {"user": bob, "action": "read_metadata", "dataset": ua_restricted}
}

# Admin is scoped to its own institution: no cross-institution override.
test_admin_cannot_download_other_institution if {
	not databank.allow with input as {"user": priya, "action": "download", "dataset": ua_restricted}
}

test_admin_cannot_read_other_institution_unshared if {
	not databank.allow with input as {"user": priya, "action": "read_metadata", "dataset": ua_restricted}
}

# --- upload ------------------------------------------------------------------

test_any_user_may_upload if {
	databank.allow with input as {"user": bob, "action": "upload", "dataset": {}}
}

# --- default deny ------------------------------------------------------------

test_user_without_institution_denied if {
	not databank.allow with input as {"user": eve, "action": "read_metadata", "dataset": ua_restricted}
}

test_unknown_action_denied if {
	not databank.allow with input as {"user": arun, "action": "delete", "dataset": ua_restricted}
}

test_empty_input_denied if {
	not databank.allow with input as {}
}

# Access policy for the Secure Research Data Bank.
#
# FastAPI sends OPA a description of the request; OPA answers allow: true/false.
# The policy lives here, outside the application, so it can be reviewed and
# tested on its own without reading any Python.
package databank

import rego.v1

# Default deny. Nothing is permitted unless a rule below explicitly allows it.
# Every other rule can only ADD permission, never remove it, so a mistake in a
# rule fails closed.
default allow := false

# Roles trusted to release restricted data within their own institution.
privileged_roles := {"data_steward", "admin"}

read_actions := {"read_metadata", "download"}

# --- helpers -----------------------------------------------------------------

user_is_owner if input.user.institution == input.dataset.owner_institution

user_is_shared_with if input.user.institution in input.dataset.shared_with

user_is_privileged if {
	some role in input.user.roles
	role in privileged_roles
}

# --- rules -------------------------------------------------------------------

# R1. Public datasets are readable and downloadable by any authenticated user,
#     whatever institution they belong to.
allow if {
	input.action in read_actions
	input.dataset.sensitivity == "public"
}

# R2. Your own institution's public and internal data is fully readable.
allow if {
	input.action in read_actions
	user_is_owner
	input.dataset.sensitivity in {"public", "internal"}
}

# R3. Restricted data owned by your institution: everyone in that institution
#     may see that it exists and read its metadata.
allow if {
	input.action == "read_metadata"
	user_is_owner
	input.dataset.sensitivity == "restricted"
}

# R4. Downloading restricted data additionally requires a data steward or an
#     admin, and only within the owning institution. A researcher in the right
#     institution is NOT enough.
allow if {
	input.action == "download"
	user_is_owner
	input.dataset.sensitivity == "restricted"
	user_is_privileged
}

# R5. An institution a dataset is shared with may read metadata only, at any
#     sensitivity. Sharing grants visibility, never the file itself.
allow if {
	input.action == "read_metadata"
	user_is_shared_with
}

# R6. Any authenticated user may upload. The owning institution is taken from
#     their verified token, not from the request, so they cannot upload on
#     another institution's behalf.
allow if input.action == "upload"

# Deliberately absent: a global admin override. An admin from one institution
# has no access to another institution's data at all. Institutions are tenant
# boundaries, so a single compromised admin account cannot cross them.

# R7. Reading or verifying the audit log requires the admin role. This is the
# one system-wide power an admin has: the log spans every institution, and
# integrity oversight is not the same as access to research data.
allow if {
	input.action == "read_audit"
	"admin" in input.user.roles
}
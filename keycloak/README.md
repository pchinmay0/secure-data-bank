# Keycloak realm configuration

The `databank` realm provides authentication for the API. `realm-export.json`
captures the realm, client and protocol mappers. Keycloak's partial export
does **not** include users, so the commands below recreate the four demo
accounts.

## What the realm contains

| Thing | Value |
|---|---|
| Realm | `databank` |
| Client | `databank-api` (confidential, direct access grants only) |
| Mappers | `databank-api-audience` (Audience), `institution` (User Attribute) |
| Realm roles | `researcher`, `data_steward`, `admin` |
| User profile attribute | `institution` — admin-writable only |

`institution` is deliberately **not** user-editable. If users could set it
themselves, anyone could move into another institution and read its data.

## Import the realm

```bash
docker compose exec keycloak /opt/keycloak/bin/kc.sh import \
  --file /opt/keycloak/data/import/realm-export.json
```

The exported client secret is masked, so regenerate it in
**Clients -> databank-api -> Credentials** and put the new value in `.env`
as `DATABANK_CLIENT_SECRET`.

## Recreate the demo users

Log the admin CLI in first (replace with the value from `.env`):

```bash
docker compose exec keycloak /opt/keycloak/bin/kcadm.sh config credentials \
  --server http://localhost:8080 --realm master \
  --user kcadmin --password "$KEYCLOAK_ADMIN_PASSWORD"
```

Then, for each user in this table:

| Username | Institution | Role | Name | Email |
|---|---|---|---|---|
| alice | UniversityA | researcher | Alice Anderson | alice@universitya.test |
| arun | UniversityA | data_steward | Arun Rao | arun@universitya.test |
| bob | LabB | researcher | Bob Brown | bob@labb.test |
| priya | LabB | admin | Priya Shah | priya@labb.test |

```bash
kcadm.sh create users -r databank -s username=alice -s enabled=true \
  -s firstName=Alice -s lastName=Anderson \
  -s email=alice@universitya.test -s emailVerified=true \
  -s attributes.institution=UniversityA

kcadm.sh set-password -r databank --username alice --new-password "<dev password>"
kcadm.sh add-roles -r databank --uusername alice --rolename researcher
```

Notes learned the hard way:

- `attributes.institution=UniversityA` must be a plain value. Passing
  `["UniversityA"]` stores a one-element list and the single-valued mapper
  emits the string `[UniversityA]`, brackets included, which breaks policy
  comparisons.
- `firstName`, `lastName` and `email` are required by the default user
  profile. Without them Keycloak raises the `VERIFY_PROFILE` required action
  and refuses to issue tokens: `Account is not fully set up`.
- Passwords must be non-temporary. A temporary password adds an
  `UPDATE_PASSWORD` required action, which blocks token requests too.

## Dev-only choices

- `start-dev` runs without HTTPS and stores data in embedded H2. Production
  needs `start`, a real database, and TLS.
- The four accounts share one password. They are local fixtures; the value is
  committed nowhere.
- The client uses the direct access grant (password grant) so tokens can be
  requested from the command line. Real clients should use the authorization
  code flow with PKCE, so the application never handles the user's password.

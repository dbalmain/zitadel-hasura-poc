/**
 * Zitadel Action: addHasuraClaims
 * Flow: Complement Token (type 2)
 * Trigger: Pre Access Token Creation (type 5)
 *
 * On every access token issuance, fetches the user's currently active role
 * from the role-validator service and injects Hasura-compatible JWT claims.
 *
 * This script is registered via the setup script (scripts/setup-zitadel.js).
 * To update it, re-run setup or patch via the Zitadel Console > Actions.
 */
function addHasuraClaims(ctx, api) {
  var userId = ctx.v1.user.id;

  var response = require("zitadel/http").fetch(
    "http://role-validator:3000/active-role/" + userId,
    {
      method: "GET",
      headers: { "Content-Type": "application/json" },
    }
  );

  // Default: unprivileged 'user' role (no active branch role selected)
  var defaultRole = "user";
  var allowedRoles = ["user"];
  var branchId = "";

  if (response.ok) {
    var data = JSON.parse(response.body);
    if (data.role) {
      // Convert DB role name (e.g. BRANCH_COORDINATOR) to a Hasura role name
      // (e.g. branch-coordinator). Hasura role names are case-insensitive but
      // conventionally lowercase-hyphenated.
      var roleName = data.role.toLowerCase().replace(/_/g, "-");
      defaultRole = roleName;
      allowedRoles = [roleName, "user"];
      branchId = data.branchId || "";
    }
  }

  api.v1.claims.setClaim("https://hasura.io/jwt/claims", {
    "x-hasura-default-role": defaultRole,
    "x-hasura-allowed-roles": allowedRoles,
    "x-hasura-user-id": userId,
    "x-hasura-branch-id": branchId,
  });
}

package playground.mp_jtw_auth;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

import javax.annotation.security.DeclareRoles;
import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;
import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.SecurityContext;

import org.eclipse.microprofile.jwt.Claim;
import org.eclipse.microprofile.jwt.ClaimValue;
import org.eclipse.microprofile.jwt.JsonWebToken;

@Path("/playground")
@Consumes("application/json")
@Produces("application/json")
@DeclareRoles({ "user-role", "mapped-user-role", "group-role" })
@PermitAll
@RequestScoped
public class PlaygroundEndpoint {

    @Context
    SecurityContext securityContext;

    @Inject
    private JsonWebToken jsonWebToken;

    @Inject
    @Claim("raw_token")
    private String rawToken;

    @Inject
    @Claim("iss")
    private String issuer;

    @Inject
    @Claim("preferred_username")
    private String username;

    @Inject
    @Claim("realm_access") // Claims#UNKNOWN; cmp. w/ jwt issued by keycloak.
    private ClaimValue<Optional<String>> unknown;

    @GET
    @Path("/secure")
    @RolesAllowed({ "user-role", "mapped-user-role", "group-role" })
    public Response secure() {
	return buildResponse("/secure");
    }

    @GET
    @Path("/unsecure")
    public Response unsecure() {
	return buildResponse("/unsecure");
    }

    private Response buildResponse(String resource) {
	Map<String, String> properties = new LinkedHashMap<>();

	properties.put("resource", resource);
	properties.put("raw_token", this.rawToken);
	properties.put("iss", this.issuer);
	properties.put("preferred_username", this.username);
	properties.put("realm_access", String.valueOf(this.unknown));
	properties.put("securityContext", getSecurityContextInfo());
	properties.put("jsonWebToken", getJsonWebTokenInfo());

	return Response.ok(properties).build();
    }

    private String getSecurityContextInfo() {
	boolean isSecurityContextSet = this.securityContext != null;
	if (!isSecurityContextSet) {
	    return "No security context.";
	}

	boolean isUserPrincipalSet = this.securityContext.getUserPrincipal() != null;
	if (!isUserPrincipalSet) {
	    return "No security principal.";
	}

	return String.format("Principal name [%s], isInUserRole [%b].",
		this.securityContext.getUserPrincipal().getName(), this.securityContext.isUserInRole("user-role"));
    }

    private String getJsonWebTokenInfo() {
	return "No jwt.";
	// Cannot use this logic, because declaration of jsonWebToken leads to
	// cdi injection failure.
	// boolean isJwtTokenSet = this.jsonWebToken != null;
	// if (!isJwtTokenSet) {
	// return "No jwt.";
	// }
	//
	// return String.format("Raw token [%s], groups [%s].",
	// this.jsonWebToken.getRawToken(),
	// this.jsonWebToken.getGroups());
    }

}

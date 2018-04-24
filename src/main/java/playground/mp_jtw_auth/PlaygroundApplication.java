package playground.mp_jtw_auth;

import javax.enterprise.context.ApplicationScoped;
import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;

import org.eclipse.microprofile.auth.LoginConfig;

@LoginConfig(authMethod = "MP-JWT", realmName = "mp-jwt-realm")
@ApplicationScoped
@ApplicationPath("/")
public class PlaygroundApplication extends Application {
    /* rely on scan at startup */
}

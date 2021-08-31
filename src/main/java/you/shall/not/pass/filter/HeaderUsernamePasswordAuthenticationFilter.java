package you.shall.not.pass.filter;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.util.StringUtils;

import javax.servlet.http.HttpServletRequest;
import java.util.Base64;

public class HeaderUsernamePasswordAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    public static final String AUTHORIZATION_HEADER = "Authorization";

    public HeaderUsernamePasswordAuthenticationFilter(AuthenticationManager authenticationManager, AuthenticationSuccessHandler authenticationSuccessHandler, AuthenticationFailureHandler authenticationFailureHandler) {
        super();
        this.setAuthenticationManager(authenticationManager);
        this.setAuthenticationSuccessHandler(authenticationSuccessHandler);
        this.setAuthenticationFailureHandler(authenticationFailureHandler);
    }

    @Override
    protected String obtainPassword(HttpServletRequest request) {
        return extractPassword(request);
    }

    @Override
    protected String obtainUsername(HttpServletRequest request) {
        return extractUsername(request);
    }

    private String[] resolveToken(HttpServletRequest request) {
        String basicToken = request.getHeader(AUTHORIZATION_HEADER);
        if (StringUtils.hasText(basicToken) && basicToken.startsWith("Basic ")) {
            byte[] decodedBytes = Base64.getDecoder().decode(basicToken.substring(6));
            String decodedString = new String(decodedBytes);
            return decodedString.split(":");
        }
        return null;
    }

    private String extractUsername(HttpServletRequest request) {
        String[] stringArray = resolveToken(request);
        if (stringArray != null && stringArray.length == 2) {
            return stringArray[0];
        }
        return null;
    }

    private String extractPassword(HttpServletRequest request) {
        String[] stringArray = resolveToken(request);
        if (stringArray != null && stringArray.length == 2) {
            return stringArray[1];
        }
        return null;
    }

}

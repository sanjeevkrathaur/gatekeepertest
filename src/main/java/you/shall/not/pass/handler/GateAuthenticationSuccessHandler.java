package you.shall.not.pass.handler;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.security.web.savedrequest.DefaultSavedRequest;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import you.shall.not.pass.filter.SecurityFilter;
import you.shall.not.pass.service.CookieService;
import you.shall.not.pass.service.CsrfProtectionService;
import you.shall.not.pass.service.SessionService;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;
import java.util.List;
import java.util.Optional;

@Component
public class GateAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private RequestCache requestCache = new HttpSessionRequestCache();

    public RequestCache getRequestCache() {
        return requestCache;
    }

    private final SessionService sessionService;
    private final CsrfProtectionService csrfProtectionService;
    private final CookieService cookieService;
    private final SessionRegistry sessionRegistry;

    public GateAuthenticationSuccessHandler(SessionService sessionService,
                                            CsrfProtectionService csrfProtectionService,
                                            CookieService cookieService, SessionRegistry sessionRegistry) {
        this.sessionService = sessionService;
        this.csrfProtectionService = csrfProtectionService;
        this.cookieService = cookieService;
        this.sessionRegistry = sessionRegistry;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        checkingSingleSignOn(request, response, authentication);

        Optional<String> optionalSession = sessionService.authenticatedSession();
        optionalSession.ifPresent(session -> {
            String csrf = csrfProtectionService.getCsrfCookie();
            cookieService.addCookie(csrf, response);
            cookieService.addCookie(session, response);
            response.setHeader(CsrfProtectionService.XSRF_GUARD_NAME, csrf.replace(CsrfProtectionService.CSRF_COOKIE_NAME, CsrfProtectionService.XSRF_GUARD_NAME));
        });

        SavedRequest savedRequest = requestCache.getRequest(request, response);

        String defaultTargetUrl = "/resources";
        if (request.getSession().getAttribute(SecurityFilter.HIGH_LEVEL_URL) != null) {
            defaultTargetUrl = String.valueOf(request.getSession().getAttribute(SecurityFilter.HIGH_LEVEL_URL));
            request.getSession().removeAttribute(SecurityFilter.HIGH_LEVEL_URL);
        } else {
            defaultTargetUrl = savedRequest != null && StringUtils.hasText(((DefaultSavedRequest) savedRequest).getRequestURI()) ?
                    ((DefaultSavedRequest) savedRequest).getRequestURI() :
                    defaultTargetUrl;
        }
        response.setHeader("targetUrl", defaultTargetUrl);
        sessionRegistry.registerNewSession(request.getSession().getId(), authentication.getPrincipal());

        if (savedRequest == null) {
            clearAuthenticationAttributes(request);
            return;
        }

        String targetUrlParam = getTargetUrlParameter();
        if (isAlwaysUseDefaultTargetUrl() || (targetUrlParam != null && StringUtils.hasText(request.getParameter(targetUrlParam)))) {
            requestCache.removeRequest(request, response);
            clearAuthenticationAttributes(request);
            return;
        }

        clearAuthenticationAttributes(request);
    }

    private void checkingSingleSignOn(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
        List<SessionInformation> sessions = sessionRegistry.getAllSessions(authentication.getPrincipal(), false);

        if (sessions != null && sessions.size() > 0) {
            HttpSession session = request.getSession(false);
            if (session != null) {
                for (SessionInformation si : sessions) {
                    if (! si.getSessionId().equals(session.getId())) {
                        session.invalidate();
                        response.setStatus(HttpStatus.UNAUTHORIZED.value());
                        response.setHeader("errorUrl", "/login?message=You already login in another place");
                    }
                }
            }
        }


    }

}

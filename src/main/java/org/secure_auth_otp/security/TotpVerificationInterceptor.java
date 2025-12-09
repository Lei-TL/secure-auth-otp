package org.secure_auth_otp.security;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.secure_auth_otp.controller.TotpController;
import org.secure_auth_otp.repository.UserRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.HandlerInterceptor;

import java.security.Principal;
import java.util.Set;

@Component
@RequiredArgsConstructor
public class TotpVerificationInterceptor implements HandlerInterceptor {

    private static final Set<String> ALLOWED_PATHS = Set.of(
            "/totp/verify",
            "/totp/setup",
            "/totp/enable",
            "/logout",
            "/error"
    );

    private final UserRepository userRepository;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        Principal principal = request.getUserPrincipal();
        if (principal == null) {
            return true;
        }

        String path = request.getRequestURI();
        if (isAllowedPath(path)) {
            return true;
        }

        return ensureTotpVerified(principal.getName(), request.getSession(false), response);
    }

    private boolean ensureTotpVerified(String email, HttpSession session, HttpServletResponse response) throws Exception {
        boolean enabled = userRepository.findByEmail(email)
                .map(u -> u.isTotpEnabled())
                .orElse(false);

        if (!enabled) {
            return true;
        }

        if (session != null) {
            Object verified = session.getAttribute(TotpController.SESSION_TOTP_VERIFIED);
            if (Boolean.TRUE.equals(verified)) {
                return true;
            }
        }

        response.sendRedirect("/totp/verify");
        return false;
    }

    private boolean isAllowedPath(String path) {
        return ALLOWED_PATHS.stream().anyMatch(path::startsWith)
                || path.startsWith("/css/")
                || path.startsWith("/js/")
                || path.startsWith("/images/");
    }
}


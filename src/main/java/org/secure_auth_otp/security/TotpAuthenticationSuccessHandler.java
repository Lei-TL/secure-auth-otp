package org.secure_auth_otp.security;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.secure_auth_otp.controller.TotpController;
import org.secure_auth_otp.entity.User;
import org.secure_auth_otp.repository.UserRepository;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class TotpAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    private final UserRepository userRepository;
    private final SimpleUrlAuthenticationSuccessHandler delegate = new SimpleUrlAuthenticationSuccessHandler("/");

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        HttpSession session = request.getSession(true);
        Optional<User> userOpt = userRepository.findByEmail(authentication.getName());

        if (userOpt.isPresent() && userOpt.get().isTotpEnabled()) {
            session.setAttribute(TotpController.SESSION_TOTP_VERIFIED, false);
            response.sendRedirect("/totp/verify");
            return;
        }

        session.setAttribute(TotpController.SESSION_TOTP_VERIFIED, true);
        delegate.onAuthenticationSuccess(request, response, authentication);
    }
}



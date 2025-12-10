package org.secure_auth_otp.config;

import lombok.RequiredArgsConstructor;
import org.secure_auth_otp.security.TotpVerificationInterceptor;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
@RequiredArgsConstructor
public class WebMvcConfig implements WebMvcConfigurer {

    private final TotpVerificationInterceptor totpVerificationInterceptor;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(totpVerificationInterceptor);
    }
}



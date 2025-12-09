package org.secure_auth_otp.config;

import lombok.RequiredArgsConstructor;
import org.secure_auth_otp.entity.User;
import org.secure_auth_otp.repository.UserRepository;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

import java.time.LocalDateTime;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final UserRepository userRepository;

    @Bean
    public UserDetailsService userDetailsService() {
        return username -> {
            User user = userRepository.findByEmail(username)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found"));

            boolean accountLocked = user.getLockoutUntil() != null
                    && user.getLockoutUntil().isAfter(LocalDateTime.now());

            return org.springframework.security.core.userdetails.User.withUsername(user.getEmail())
                    .password(user.getPasswordHash())
                    .authorities("ROLE_USER")        // sau này dễ mở rộng role
                    .accountLocked(accountLocked)    // khoá tạm nếu bị lockout
                    .disabled(!user.isActive())      // chưa verify email -> disabled
                    .build();
        };
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(
            UserDetailsService userDetailsService,
            PasswordEncoder passwordEncoder
    ) {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService);
        provider.setPasswordEncoder(passwordEncoder);
        return provider;
    }


    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            DaoAuthenticationProvider authProvider
    ) throws Exception {

        http
                // ĐỂ DEMO CHO NHANH: tắt CSRF (prod thì nên bật + thêm input _csrf vào form)
                .csrf(csrf -> csrf.disable())

                .authenticationProvider(authProvider)

                .authorizeHttpRequests(auth -> auth
                        // Cho phép truy cập không cần login:
                        .requestMatchers(
                                "/login",
                                "/register",
                                "/register/**",      // /register/verify-otp
                                "/css/**",
                                "/js/**",
                                "/images/**"
                        ).permitAll()

                        // tất cả URL còn lại phải đăng nhập
                        .anyRequest().authenticated()
                )

                .formLogin(form -> form
                        .loginPage("/login")          // view login.html
                        .loginProcessingUrl("/login") // <form action="/login" ...> trong login.html
                        .defaultSuccessUrl("/", true) // login xong về trang chủ
                        .failureUrl("/login?error")   // khi sai user/pass
                        .permitAll()
                )

                .logout(logout -> logout
                        .logoutUrl("/logout")
                        .logoutSuccessUrl("/login?logout")
                        .permitAll()
                );

        return http.build();
    }
}

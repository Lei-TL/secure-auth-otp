package org.secure_auth_otp.service.impl;

import lombok.RequiredArgsConstructor;
import org.apache.commons.codec.binary.Base32;
import org.secure_auth_otp.entity.User;
import org.secure_auth_otp.repository.UserRepository;
import org.secure_auth_otp.security.totp.TotpGenerator;
import org.secure_auth_otp.service.TotpService;
import org.secure_auth_otp.service.dto.TotpSetup;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.security.SecureRandom;
import java.time.Instant;
import java.time.LocalDateTime;

@Service
@RequiredArgsConstructor
public class TotpServiceImpl implements TotpService {

    private static final Logger log = LoggerFactory.getLogger(TotpServiceImpl.class);

    private static final int SECRET_BYTES = 20;
    private static final int VERIFY_WINDOW = 1;
    private static final int MAX_TOTP_FAILS = 5;
    private static final int LOCK_MINUTES = 5;
    private static final String ISSUER = "OTP-Security-Lab";

    private final UserRepository userRepository;
    private final TotpGenerator totpGenerator;
    private final SecureRandom secureRandom = new SecureRandom();
    private final Base32 base32 = new Base32();

    @Override
    public TotpSetup startSetup(String email) {
        String secret = generateSecret();
        String otpauthUrl = buildOtpauth(secret, email);
        log.info("TOTP setup initiated email={}", maskEmail(email));
        return new TotpSetup(secret, otpauthUrl);
    }

    @Override
    @Transactional
    public void enableTotp(String email, String secretBase32, String otpInput) {
        User user = findUser(email);
        if (!totpGenerator.verify(secretBase32, otpInput, Instant.now(), VERIFY_WINDOW)) {
            log.warn("TOTP enable failed reason=wrong_otp email={}", maskEmail(email));
            throw new RuntimeException("Mã TOTP không hợp lệ.");
        }

        user.setTotpSecret(secretBase32);
        user.setTotpEnabled(true);
        user.setTotpFailedAttempts(0);
        user.setTotpLockoutUntil(null);
        userRepository.save(user);

        log.info("TOTP enabled email={}", maskEmail(email));
    }

    @Override
    @Transactional
    public void verifyLogin(String email, String otpInput) {
        User user = findUser(email);
        if (!user.isTotpEnabled()) {
            return;
        }

        LocalDateTime now = LocalDateTime.now();
        if (user.getTotpLockoutUntil() != null && user.getTotpLockoutUntil().isAfter(now)) {
            log.warn("TOTP verify blocked reason=lockout email={} until={}", maskEmail(email), user.getTotpLockoutUntil());
            throw new RuntimeException("Tài khoản đang bị khoá tạm do nhập sai TOTP quá nhiều.");
        }

        boolean ok = totpGenerator.verify(user.getTotpSecret(), otpInput, Instant.now(), VERIFY_WINDOW);
        if (!ok) {
            int fails = user.getTotpFailedAttempts() + 1;
            user.setTotpFailedAttempts(fails);
            if (fails >= MAX_TOTP_FAILS) {
                user.setTotpLockoutUntil(now.plusMinutes(LOCK_MINUTES));
            }
            userRepository.save(user);
            log.warn("TOTP verify failed email={} attempts={} lockoutUntil={}",
                    maskEmail(email), fails, user.getTotpLockoutUntil());
            throw new RuntimeException("Mã TOTP không đúng.");
        }

        user.setTotpFailedAttempts(0);
        user.setTotpLockoutUntil(null);
        userRepository.save(user);
        log.info("TOTP verify success email={}", maskEmail(email));
    }

    @Override
    public boolean isTotpEnabled(String email) {
        return userRepository.findByEmail(email)
                .map(User::isTotpEnabled)
                .orElse(false);
    }

    private String generateSecret() {
        byte[] bytes = new byte[SECRET_BYTES];
        secureRandom.nextBytes(bytes);
        String encoded = base32.encodeToString(bytes);
        return encoded.replace("=", "").toUpperCase();
    }

    private String buildOtpauth(String secret, String email) {
        String label = ISSUER + ":" + email;
        return String.format("otpauth://totp/%s?secret=%s&issuer=%s&digits=6&period=30&algorithm=SHA1",
                urlEncode(label), secret, urlEncode(ISSUER));
    }

    private User findUser(String email) {
        return userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User không tồn tại"));
    }

    private String urlEncode(String input) {
        return java.net.URLEncoder.encode(input, java.nio.charset.StandardCharsets.UTF_8);
    }

    private String maskEmail(String email) {
        int atIndex = email.indexOf('@');
        if (atIndex <= 1) return "***";
        return email.charAt(0) + "***" + email.substring(atIndex);
    }
}


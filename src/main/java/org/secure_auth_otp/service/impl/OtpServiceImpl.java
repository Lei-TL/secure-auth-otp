package org.secure_auth_otp.service.impl;

import lombok.RequiredArgsConstructor;
import org.secure_auth_otp.entity.OtpToken;
import org.secure_auth_otp.repository.OtpTokenRepository;
import org.secure_auth_otp.service.EmailService;
import org.secure_auth_otp.service.OtpService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Random;

@Service
@RequiredArgsConstructor
public class OtpServiceImpl implements OtpService {

    private static final Logger log = LoggerFactory.getLogger(org.secure_auth_otp.service.OtpService.class);

    private final OtpTokenRepository otpTokenRepository;
    private final PasswordEncoder passwordEncoder;
    private final EmailService emailService;

    private static final int OTP_TTL_MINUTES = 5;
    private static final int MAX_OTP_ATTEMPTS = 5;
    private static final int MAX_OTP_PER_15_MIN = 3;

    @Override
    public int getOtpTtlMinutes() {
        return OTP_TTL_MINUTES;
    }

    @Override
    public int getMaxOtpAttempts() {
        return MAX_OTP_ATTEMPTS;
    }

    @Override
    @Transactional
    public void sendOtp(String email, String purpose) {
        generateAndSendOtp(email, purpose, false);
    }

    @Override
    @Transactional
    public void resendOtp(String email, String purpose) {
        generateAndSendOtp(email, purpose, true);
    }

    @Override
    public boolean verifyOtp(String email, String purpose, String inputOtp) {
        List<OtpToken> tokens = otpTokenRepository.findLatestByEmailAndPurpose(email, purpose);
        if (tokens.isEmpty()) {
            log.warn("OTP verify failed reason=no_token email={} purpose={}", maskEmail(email), purpose);
            throw new RuntimeException("OTP không tồn tại hoặc đã bị ghi đè.");
        }

        OtpToken token = tokens.get(0); // OTP mới nhất
        LocalDateTime now = LocalDateTime.now();

        if (token.isUsed()) {
            log.warn("OTP verify failed reason=used email={} purpose={}", maskEmail(email), purpose);
            throw new RuntimeException("OTP đã được sử dụng.");
        }

        if (token.getExpiresAt().isBefore(now)) {
            log.warn("OTP verify failed reason=expired email={} purpose={} expiresAt={}", maskEmail(email), purpose, token.getExpiresAt());
            throw new RuntimeException("OTP đã hết hạn.");
        }

        if (token.getAttempts() >= token.getMaxAttempts()) {
            log.warn("OTP verify failed reason=max_attempts email={} purpose={} attempts={}", maskEmail(email), purpose, token.getAttempts());
            throw new RuntimeException("Bạn đã nhập sai OTP quá số lần cho phép.");
        }

        boolean match = passwordEncoder.matches(inputOtp, token.getOtpHash());
        if (!match) {
            token.setAttempts(token.getAttempts() + 1);
            otpTokenRepository.save(token);

            // LOG lần nhập sai OTP để đưa vào báo cáo
            log.warn("OTP verify failed reason=wrong_code email={} purpose={} attempts={}",
                    maskEmail(email), purpose, token.getAttempts());

            throw new RuntimeException("OTP không đúng.");
        }

        token.setUsed(true);
        otpTokenRepository.save(token);

        log.info("OTP verify success email={} purpose={}", maskEmail(email), purpose);
        return true;
    }

    private void generateAndSendOtp(String email, String purpose, boolean isResend) {
        LocalDateTime now = LocalDateTime.now();

        // 1. Rate limiting: tối đa 3 OTP / 15 phút / email + purpose
        LocalDateTime from = now.minusMinutes(15);
        long count = otpTokenRepository.countRecentOtp(email, purpose, from);
        if (count >= MAX_OTP_PER_15_MIN) {
            log.warn("OTP request blocked reason=rate_limit email={} purpose={} count15m={}", maskEmail(email), purpose, count);
            throw new RuntimeException("Yêu cầu OTP quá nhiều lần, vui lòng thử lại sau.");
        }

        // 2. Vô hiệu hoá OTP cũ
        int invalidated = otpTokenRepository.invalidateActiveTokens(email, purpose);

        // 3. Sinh OTP mới
        String otp = String.format("%06d", new Random().nextInt(1_000_000));
        String otpHash = passwordEncoder.encode(otp);

        // 4. Tính resendCount (để log)
        int resendCount = 0;
        if (isResend) {
            OtpToken latest = otpTokenRepository.findLatestByEmailAndPurpose(email, purpose)
                    .stream()
                    .findFirst()
                    .orElse(null);
            if (latest != null) {
                resendCount = latest.getResendCount() + 1;
            }
        }

        // 5. Lưu OTP
        OtpToken token = new OtpToken();
        token.setEmail(email);
        token.setPurpose(purpose);
        token.setOtpHash(otpHash);
        token.setExpiresAt(now.plusMinutes(OTP_TTL_MINUTES));
        token.setMaxAttempts(MAX_OTP_ATTEMPTS);
        token.setResendCount(resendCount);
        otpTokenRepository.save(token);

        // 6. Gửi mail
        emailService.sendOtpEmail(email, otp, purpose);

        log.info("OTP created email={} purpose={} expiresAt={} resendCount={} invalidatedPrevious={}",
                maskEmail(email), purpose, token.getExpiresAt(), resendCount, invalidated);
    }

    private String maskEmail(String email) {
        int atIndex = email.indexOf('@');
        if (atIndex <= 1) return "***";
        return email.charAt(0) + "***" + email.substring(atIndex);
    }
}


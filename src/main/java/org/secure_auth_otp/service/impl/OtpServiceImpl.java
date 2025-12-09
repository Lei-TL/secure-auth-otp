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
    private static final int MAX_OTP_PER_15_MIN = 3;

    public void sendOtp(String email, String purpose) {
        // 1. Rate limiting: tối đa 3 OTP / 15 phút / email + purpose
        LocalDateTime from = LocalDateTime.now().minusMinutes(15);
        long count = otpTokenRepository.countRecentOtp(email, purpose, from);
        if (count >= MAX_OTP_PER_15_MIN) {
            throw new RuntimeException("Yêu cầu OTP quá nhiều lần, vui lòng thử lại sau.");
        }

        // 2. Sinh OTP
        String otp = String.format("%06d", new Random().nextInt(1_000_000));

        // 3. Hash OTP
        String otpHash = passwordEncoder.encode(otp);

        // 4. Lưu DB (OTP mới -> là OTP hợp lệ duy nhất)
        OtpToken token = new OtpToken();
        token.setEmail(email);
        token.setPurpose(purpose);
        token.setOtpHash(otpHash);
        token.setExpiresAt(LocalDateTime.now().plusMinutes(OTP_TTL_MINUTES));
        otpTokenRepository.save(token);

        // 5. Gửi mail
        emailService.sendOtpEmail(email, otp, purpose);

        log.info("Sent OTP for email={} purpose={} at={}", maskEmail(email), purpose, token.getCreatedAt());
    }

    public boolean verifyOtp(String email, String purpose, String inputOtp) {
        List<OtpToken> tokens = otpTokenRepository.findLatestByEmailAndPurpose(email, purpose);
        if (tokens.isEmpty()) {
            log.warn("OTP verify failed (no token) email={} purpose={}", maskEmail(email), purpose);
            throw new RuntimeException("OTP không tồn tại hoặc đã bị ghi đè.");
        }

        OtpToken token = tokens.get(0); // OTP mới nhất

        if (token.isUsed()) {
            log.warn("OTP verify failed (used) email={} purpose={}", maskEmail(email), purpose);
            throw new RuntimeException("OTP đã được sử dụng.");
        }

        if (token.getExpiresAt().isBefore(LocalDateTime.now())) {
            log.warn("OTP verify failed (expired) email={} purpose={}", maskEmail(email), purpose);
            throw new RuntimeException("OTP đã hết hạn.");
        }

        if (token.getAttempts() >= token.getMaxAttempts()) {
            log.warn("OTP verify failed (too many attempts) email={} purpose={}", maskEmail(email), purpose);
            throw new RuntimeException("Bạn đã nhập sai OTP quá số lần cho phép.");
        }

        boolean match = passwordEncoder.matches(inputOtp, token.getOtpHash());
        if (!match) {
            token.setAttempts(token.getAttempts() + 1);
            otpTokenRepository.save(token);

            // LOG lần nhập sai OTP để đưa vào báo cáo
            log.warn("OTP verify failed (wrong code) email={} purpose={} attempts={}",
                    maskEmail(email), purpose, token.getAttempts());

            throw new RuntimeException("OTP không đúng.");
        }

        token.setUsed(true);
        otpTokenRepository.save(token);

        log.info("OTP verify success email={} purpose={}", maskEmail(email), purpose);
        return true;
    }

    private String maskEmail(String email) {
        int atIndex = email.indexOf('@');
        if (atIndex <= 1) return "***";
        return email.charAt(0) + "***" + email.substring(atIndex);
    }
}


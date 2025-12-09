package org.secure_auth_otp.service.impl;

import lombok.RequiredArgsConstructor;
import org.secure_auth_otp.service.EmailService;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class EmailServiceImpl implements EmailService {

    private final JavaMailSender mailSender;

    public void sendOtpEmail(String to, String otp, String purpose) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject("[Security Demo] OTP cho " + purpose);
        message.setText("""
                Mã OTP của bạn là: %s
                Mã có hiệu lực trong 5 phút và cho phép tối đa 5 lần nhập sai.
                Nếu không phải bạn yêu cầu, vui lòng bỏ qua email này.
                """.formatted(otp));
        mailSender.send(message);
    }
}

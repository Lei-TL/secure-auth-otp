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
        message.setText("Mã OTP của bạn là: " + otp + "\nMã có hiệu lực trong 5 phút.");
        mailSender.send(message);
    }
}

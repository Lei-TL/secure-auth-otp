package org.secure_auth_otp.service.impl;

import lombok.RequiredArgsConstructor;
import org.secure_auth_otp.entity.User;
import org.secure_auth_otp.repository.UserRepository;
import org.secure_auth_otp.service.OtpService;
import org.secure_auth_otp.service.UserService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final OtpService otpService;

    // Đăng ký: tạo user + gửi OTP xác thực email
    public void register(String email, String rawPassword) {
        if (userRepository.findByEmail(email).isPresent()) {
            throw new RuntimeException("Email đã tồn tại");
        }

        User user = new User();
        user.setEmail(email);
        user.setPasswordHash(passwordEncoder.encode(rawPassword));
        user.setActive(false);
        userRepository.save(user);

        otpService.sendOtp(email, "SIGNUP_VERIFY_EMAIL");
    }

    // Verify OTP signup
    public void verifySignupOtp(String email, String otp) {
        boolean ok = otpService.verifyOtp(email, "SIGNUP_VERIFY_EMAIL", otp);
        if (!ok) {
            throw new RuntimeException("OTP không hợp lệ");
        }
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User không tồn tại"));
        user.setActive(true);
        userRepository.save(user);
    }

    // Gửi OTP cho đổi mật khẩu (2FA)
    public void sendChangePasswordOtp(String email) {
        otpService.sendOtp(email, "CHANGE_PASSWORD_2FA");
    }

    // Đổi mật khẩu sau khi verify OTP (2FA)
    public void changePasswordWithOtp(String email, String otp, String newPassword) {
        boolean ok = otpService.verifyOtp(email, "CHANGE_PASSWORD_2FA", otp);
        if (!ok) {
            throw new RuntimeException("OTP không hợp lệ");
        }
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User không tồn tại"));
        user.setPasswordHash(passwordEncoder.encode(newPassword));
        userRepository.save(user);
    }
}



package org.secure_auth_otp.controller;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.secure_auth_otp.service.UserService;
import org.secure_auth_otp.service.OtpService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

@Controller
@RequiredArgsConstructor
public class TwoFAController {

    private final UserService userService;
    private final OtpService otpService;

    // Trang yêu cầu đổi mật khẩu: bấm nút gửi OTP
    @GetMapping("/change-password")
    public String showChangePasswordPage(Model model) {
        model.addAttribute("step", "REQUEST_OTP");
        return "change-password"; // anh có thể dùng twofa.html hoặc file riêng
    }

    @PostMapping("/change-password/send-otp")
    public String sendChangePasswordOtp(Principal principal, Model model) {
        String email = principal.getName(); // hoặc lấy từ UserDetails
        userService.sendChangePasswordOtp(email);
        model.addAttribute("email", email);
        model.addAttribute("purpose", "CHANGE_PASSWORD_2FA");
        appendOtpMeta(model);
        return "twofa"; // view nhập OTP + mật khẩu mới
    }

    @PostMapping("/change-password/verify-otp")
    public String handleChangePasswordWithOtp(Principal principal,
                                              @RequestParam String otp,
                                              @RequestParam String newPassword,
                                              Model model) {
        String email = principal.getName();
        try {
            userService.changePasswordWithOtp(email, otp, newPassword);
            model.addAttribute("message", "Đổi mật khẩu thành công.");
            return "login";
        } catch (Exception e) {
            model.addAttribute("email", email);
            model.addAttribute("purpose", "CHANGE_PASSWORD_2FA");
            model.addAttribute("error", e.getMessage());
            appendOtpMeta(model);
            return "twofa";
        }
    }

    @PostMapping("/change-password/resend-otp")
    public String resendChangePasswordOtp(Principal principal, Model model) {
        String email = principal.getName();
        userService.resendChangePasswordOtp(email);
        model.addAttribute("email", email);
        model.addAttribute("purpose", "CHANGE_PASSWORD_2FA");
        model.addAttribute("message", "Đã gửi lại OTP cho yêu cầu đổi mật khẩu.");
        appendOtpMeta(model);
        return "twofa";
    }

    private void appendOtpMeta(Model model) {
        model.addAttribute("otpTtlMinutes", otpService.getOtpTtlMinutes());
        model.addAttribute("maxOtpAttempts", otpService.getMaxOtpAttempts());
    }

    @Data
    public static class ChangePasswordForm {
        private String otp;
        private String newPassword;
    }
}


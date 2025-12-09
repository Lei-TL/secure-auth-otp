package org.secure_auth_otp.controller;

import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.secure_auth_otp.dto.RegisterForm;
import org.secure_auth_otp.service.OtpService;
import org.secure_auth_otp.service.UserService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;
    private final OtpService otpService;

    // Trang đăng ký
    @GetMapping("/register")
    public String showRegisterForm(Model model) {
        model.addAttribute("registerForm", new RegisterForm());
        return "register";
    }

    @PostMapping("/register")
    public String handleRegister(@ModelAttribute RegisterForm form, Model model) {
        try {
            userService.register(form.getEmail(), form.getPassword());
            model.addAttribute("email", form.getEmail());
            model.addAttribute("purpose", "SIGNUP_VERIFY_EMAIL");
            appendOtpMeta(model);
            return "twofa"; // dùng chung view OTP
        } catch (Exception e) {
            model.addAttribute("error", e.getMessage());
            model.addAttribute("registerForm", form);
            return "register";
        }
    }

    // Verify OTP signup
    @PostMapping("/register/verify-otp")
    public String verifySignupOtp(@RequestParam String email,
                                  @RequestParam String otp,
                                  Model model) {
        try {
            userService.verifySignupOtp(email, otp);
            model.addAttribute("message", "Xác thực email thành công, mời bạn đăng nhập.");
            return "login";
        } catch (Exception e) {
            model.addAttribute("email", email);
            model.addAttribute("purpose", "SIGNUP_VERIFY_EMAIL");
            model.addAttribute("error", e.getMessage());
            appendOtpMeta(model);
            return "twofa";
        }
    }

    @PostMapping("/register/resend-otp")
    public String resendSignupOtp(@RequestParam String email, Model model) {
        userService.resendSignupOtp(email);
        model.addAttribute("email", email);
        model.addAttribute("purpose", "SIGNUP_VERIFY_EMAIL");
        model.addAttribute("message", "Đã gửi lại OTP. Vui lòng kiểm tra email.");
        appendOtpMeta(model);
        return "twofa";
    }

    // Trang login (Spring Security sẽ xử lý POST /login)
    @GetMapping("/login")
    public String showLoginForm() {
        return "login";
    }

    private void appendOtpMeta(Model model) {
        model.addAttribute("otpTtlMinutes", otpService.getOtpTtlMinutes());
        model.addAttribute("maxOtpAttempts", otpService.getMaxOtpAttempts());
    }

}


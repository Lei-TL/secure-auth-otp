package org.secure_auth_otp.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@Controller
public class LogsController {

    @GetMapping("/logs")
    public String showLogs(Model model) {
        // Demo data; real logs are in application logs/console.
        List<Map<String, String>> logs = List.of(
                Map.of("time", LocalDateTime.now().minusMinutes(2).toString(), "email", "mask@example.com", "event", "OTP_CREATED", "detail", "purpose=SIGNUP_VERIFY_EMAIL"),
                Map.of("time", LocalDateTime.now().minusMinutes(1).toString(), "email", "mask@example.com", "event", "OTP_FAILED", "detail", "reason=wrong_code"),
                Map.of("time", LocalDateTime.now().toString(), "email", "mask@example.com", "event", "TOTP_FAILED", "detail", "reason=wrong_code")
        );
        model.addAttribute("logs", logs);
        return "logs";
    }
}



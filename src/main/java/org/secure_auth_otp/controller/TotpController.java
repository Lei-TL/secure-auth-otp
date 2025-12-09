package org.secure_auth_otp.controller;

import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import org.secure_auth_otp.service.TotpService;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.security.Principal;

@Controller
@RequiredArgsConstructor
public class TotpController {

    public static final String SESSION_TOTP_VERIFIED = "TOTP_VERIFIED";
    public static final String SESSION_TOTP_SETUP_SECRET = "TOTP_SETUP_SECRET";

    private final TotpService totpService;

    @GetMapping("/totp/setup")
    public String showSetup(Model model, Principal principal, HttpSession session) {
        if (totpService.isTotpEnabled(principal.getName())) {
            return "redirect:/";
        }
        var setup = totpService.startSetup(principal.getName());
        session.setAttribute(SESSION_TOTP_SETUP_SECRET, setup.secretBase32());
        model.addAttribute("secret", setup.secretBase32());
        model.addAttribute("otpauth", setup.otpauthUrl());
        return "totp-setup";
    }

    @PostMapping("/totp/enable")
    public String enableTotp(@RequestParam String otp,
                             Principal principal,
                             HttpSession session,
                             Model model) {
        String secret = (String) session.getAttribute(SESSION_TOTP_SETUP_SECRET);
        if (secret == null) {
            model.addAttribute("error", "Hết phiên thiết lập, vui lòng tạo lại secret.");
            return "redirect:/totp/setup";
        }

        try {
            totpService.enableTotp(principal.getName(), secret, otp);
            session.removeAttribute(SESSION_TOTP_SETUP_SECRET);
            session.setAttribute(SESSION_TOTP_VERIFIED, true);
            return "redirect:/";
        } catch (Exception e) {
            model.addAttribute("secret", secret);
            model.addAttribute("error", e.getMessage());
            return "totp-setup";
        }
    }

    @GetMapping("/totp/verify")
    public String showVerify(Model model, Principal principal) {
        if (!totpService.isTotpEnabled(principal.getName())) {
            return "redirect:/";
        }
        return "totp-verify";
    }

    @PostMapping("/totp/verify")
    public String handleVerify(@RequestParam String otp,
                               Principal principal,
                               HttpSession session,
                               Model model) {
        try {
            totpService.verifyLogin(principal.getName(), otp);
            session.setAttribute(SESSION_TOTP_VERIFIED, true);
            return "redirect:/";
        } catch (Exception e) {
            model.addAttribute("error", e.getMessage());
            return "totp-verify";
        }
    }
}


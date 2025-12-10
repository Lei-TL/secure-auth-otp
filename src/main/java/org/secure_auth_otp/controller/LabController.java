package org.secure_auth_otp.controller;

import lombok.RequiredArgsConstructor;
import org.secure_auth_otp.security.totp.HotpGenerator;
import org.secure_auth_otp.security.totp.TotpGenerator;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

@Controller
@RequiredArgsConstructor
public class LabController {

    private final HotpGenerator hotpGenerator;
    private final TotpGenerator totpGenerator;

    @GetMapping("/lab/hotp")
    public String hotpForm(Model model) {
        model.addAttribute("action", "generate");
        model.addAttribute("digits", 6);
        model.addAttribute("window", 1);
        return "hotp-lab";
    }

    @PostMapping("/lab/hotp")
    public String hotpLab(@RequestParam String secret,
                          @RequestParam(defaultValue = "0") long counter,
                          @RequestParam(defaultValue = "6") int digits,
                          @RequestParam(defaultValue = "generate") String action,
                          @RequestParam(required = false) String otp,
                          @RequestParam(defaultValue = "1") int window,
                          Model model) {
        model.addAttribute("secret", secret);
        model.addAttribute("counter", counter);
        model.addAttribute("digits", digits);
        model.addAttribute("action", action);
        model.addAttribute("window", window);
        model.addAttribute("otpInput", otp);

        if ("verify".equalsIgnoreCase(action)) {
            HotpGenerator.DebugInfo result = hotpGenerator.verify(secret, counter, otp, window, digits);
            model.addAttribute("verified", result != null);
            if (result != null) {
                model.addAttribute("debug", result);
            }
        } else {
            HotpGenerator.DebugInfo debug = hotpGenerator.generateDebug(secret, counter, digits);
            model.addAttribute("otp", debug.otp());
            model.addAttribute("debug", debug);
        }

        return "hotp-lab";
    }

    @GetMapping("/lab/totp")
    public String totpForm(Model model) {
        model.addAttribute("digits", 6);
        model.addAttribute("timeStep", 30);
        model.addAttribute("window", 1);
        return "totp-lab";
    }

    @PostMapping("/lab/totp")
    public String totpLab(@RequestParam String secret,
                          @RequestParam(defaultValue = "30") int timeStep,
                          @RequestParam(defaultValue = "6") int digits,
                          @RequestParam(defaultValue = "1") int window,
                          Model model) {
        Instant now = Instant.now();
        TotpGenerator.DebugInfo current = totpGenerator.generateDebug(secret, now, timeStep, digits);

        List<TotpGenerator.DebugInfo> windowList = new ArrayList<>();
        for (int i = -window; i <= window; i++) {
            long counter = current.counter() + i;
            TotpGenerator.DebugInfo info = totpGenerator.generateDebug(secret,
                    Instant.ofEpochSecond((counter) * timeStep), timeStep, digits);
            windowList.add(info);
        }

        model.addAttribute("secret", secret);
        model.addAttribute("digits", digits);
        model.addAttribute("timeStep", timeStep);
        model.addAttribute("window", window);
        model.addAttribute("unixTime", now.getEpochSecond());
        model.addAttribute("current", current);
        model.addAttribute("windowList", windowList);

        return "totp-lab";
    }
}



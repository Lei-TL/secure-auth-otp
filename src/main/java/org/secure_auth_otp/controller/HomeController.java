package org.secure_auth_otp.controller;

import lombok.RequiredArgsConstructor;
import org.secure_auth_otp.repository.UserRepository;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import java.security.Principal;

@Controller
@RequiredArgsConstructor
public class HomeController {

    private final UserRepository userRepository;

    @GetMapping("/")
    public String home(Principal principal, Model model) {
        if (principal != null) {
            model.addAttribute("email", principal.getName());
            userRepository.findByEmail(principal.getName())
                    .ifPresent(user -> model.addAttribute("totpEnabled", user.isTotpEnabled()));
        }
        return "home";
    }
}


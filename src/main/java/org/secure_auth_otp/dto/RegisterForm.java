package org.secure_auth_otp.dto;

import lombok.Data;

@Data
public class RegisterForm {
    private String email;
    private String password;
}

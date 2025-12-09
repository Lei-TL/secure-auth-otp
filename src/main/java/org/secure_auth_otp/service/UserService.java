package org.secure_auth_otp.service;

public interface UserService {

    void register(String email, String rawPassword);

    void verifySignupOtp(String email, String otp);

    void resendSignupOtp(String email);

    void sendChangePasswordOtp(String email);

    void resendChangePasswordOtp(String email);

    void changePasswordWithOtp(String email, String otp, String newPassword);

}


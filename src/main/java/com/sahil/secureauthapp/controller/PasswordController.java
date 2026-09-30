package com.sahil.secureauthapp.controller;

import com.sahil.secureauthapp.entity.User;
import com.sahil.secureauthapp.repository.UserRepository;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class PasswordController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public PasswordController(UserRepository userRepository,
                              PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @GetMapping("/change-password")
    public String showChangePasswordPage() {
        return "change-password";
    }

    @PostMapping("/change-password")
    public String changePassword(
            @RequestParam String currentPassword,
            @RequestParam String newPassword,
            @RequestParam String confirmPassword,
            Authentication authentication,
            Model model) {

        String username = authentication.getName();

        User user = userRepository.findByUsername(username)
                .orElseThrow(() ->
                        new IllegalArgumentException("User not found"));

        // Verify current password
        if (!passwordEncoder.matches(
                currentPassword,
                user.getPassword())) {

            model.addAttribute("error",
                    "Current password is incorrect");

            return "change-password";
        }

        // Check new password length
        if (newPassword.length() < 8) {
            model.addAttribute("error",
                    "Password must be at least 8 characters");

            return "change-password";
        }

        // Check uppercase
        if (!newPassword.matches(".*[A-Z].*")) {
            model.addAttribute("error",
                    "Password must contain at least one uppercase letter");

            return "change-password";
        }

        // Check lowercase
        if (!newPassword.matches(".*[a-z].*")) {
            model.addAttribute("error",
                    "Password must contain at least one lowercase letter");

            return "change-password";
        }

        // Check number
        if (!newPassword.matches(".*\\d.*")) {
            model.addAttribute("error",
                    "Password must contain at least one number");

            return "change-password";
        }

        // Check special character
        if (!newPassword.matches(".*[^a-zA-Z0-9].*")) {
            model.addAttribute("error",
                    "Password must contain at least one special character");

            return "change-password";
        }

        // Check confirmation
        if (!newPassword.equals(confirmPassword)) {
            model.addAttribute("error",
                    "New passwords do not match");

            return "change-password";
        }

        // Prevent reusing the current password
        if (passwordEncoder.matches(
                newPassword,
                user.getPassword())) {

            model.addAttribute("error",
                    "New password must be different from current password");

            return "change-password";
        }

        // Hash the new password with BCrypt
        user.setPassword(
                passwordEncoder.encode(newPassword)
        );

        userRepository.save(user);

        model.addAttribute("success",
                "Password changed successfully");

        return "change-password";
    }
}
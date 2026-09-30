package com.sahil.secureauthapp.controller;

import com.sahil.secureauthapp.entity.User;
import com.sahil.secureauthapp.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
public class AuthController {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;

    public AuthController(UserRepository userRepository,
                          PasswordEncoder passwordEncoder) {
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @GetMapping("/register")
    public String showRegisterPage() {
        return "register";
    }

    @PostMapping("/register")
    public String registerUser(
            @RequestParam String username,
            @RequestParam String password,
            Model model) {

        // Username validation
        if (username == null || username.trim().isEmpty()) {
            model.addAttribute("error",
                    "Username cannot be empty");
            return "register";
        }

        // Password length validation
        if (password == null || password.length() < 8) {
            model.addAttribute("error",
                    "Password must be at least 8 characters");
            return "register";
        }

        // Uppercase validation
        if (!password.matches(".*[A-Z].*")) {
            model.addAttribute("error",
                    "Password must contain at least one uppercase letter");
            return "register";
        }

        // Lowercase validation
        if (!password.matches(".*[a-z].*")) {
            model.addAttribute("error",
                    "Password must contain at least one lowercase letter");
            return "register";
        }

        // Number validation
        if (!password.matches(".*\\d.*")) {
            model.addAttribute("error",
                    "Password must contain at least one number");
            return "register";
        }

        // Special character validation
        if (!password.matches(".*[^a-zA-Z0-9].*")) {
            model.addAttribute("error",
                    "Password must contain at least one special character");
            return "register";
        }

        // Duplicate username validation
        if (userRepository.existsByUsername(username.trim())) {
            model.addAttribute("error",
                    "Username already exists");
            return "register";
        }

        // Create user with BCrypt encrypted password
        User user = new User(
                username.trim(),
                passwordEncoder.encode(password),
                "USER"
        );

        userRepository.save(user);

        return "redirect:/login?registered";
    }

    @GetMapping("/login")
    public String showLoginPage() {
        return "login";
    }
}
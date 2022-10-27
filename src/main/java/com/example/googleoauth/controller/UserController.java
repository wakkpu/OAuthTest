package com.example.googleoauth.controller;

import com.example.googleoauth.exception.ResourceNotFoundException;
import com.example.googleoauth.model.User;
import com.example.googleoauth.repository.UserRepository;
import com.example.googleoauth.security.oauth2.CurrentUser;
import com.example.googleoauth.security.oauth2.UserPrincipal;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserController {

    @Autowired
    private UserRepository userRepository;

    @GetMapping("/user/me")
    @PreAuthorize("hasRole('USER')")
    public User getCurrentUser(@CurrentUser UserPrincipal userPrincipal) {
        return userRepository.findById(userPrincipal.getId()).orElseThrow(
                () -> new ResourceNotFoundException("User", "id", userPrincipal.getId())
        );
    }
}

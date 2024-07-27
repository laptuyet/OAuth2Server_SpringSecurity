package com.demo.oauth2.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.security.Principal;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api")
public class DashboardController {

//    @PreAuthorize("hasAnyRole('ROLE_MANAGER','ROLE_ADMIN','ROLE_USER')")
    @PreAuthorize("hasAuthority('SCOPE_READ')")
    @GetMapping("/welcome-message")
    public ResponseEntity<String> getFirstWelcomeMessage(Authentication authentication) {
        return ResponseEntity.ok("Welcome to the JWT Tutorial:" + authentication.getName() + "with scope:" + authentication.getAuthorities());
    }

//    @PreAuthorize("hasRole('ROLE_MANAGER')")
    @PreAuthorize("hasAuthority('SCOPE_READ')")
    @GetMapping("/manager-message")
    public ResponseEntity<String> getManagerData(Principal principal) {
        return ResponseEntity.ok("Manager::" + principal.getName());

    }

//    @PreAuthorize("hasRole('ROLE_ADMIN')")
    @PreAuthorize("hasAnyAuthority('SCOPE_WRITE' ,'SCOPE_READ')")
    @PostMapping("/admin-message")
    public ResponseEntity<String> getAdminData(String message, Principal principal) {
        return ResponseEntity.ok("Admin::" + principal.getName() + " has this message:" + message);

    }
}

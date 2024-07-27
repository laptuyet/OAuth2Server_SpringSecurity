package com.demo.oauth2.dto;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotEmpty;

public record UserRegistration(
        @NotEmpty(message = "User Name must not be empty")
        String username,

        String phone,

        @NotEmpty(message = "User email must not be empty") //Neither null nor 0 size
        @Email(message = "Invalid email format")
        String email,

        @NotEmpty(message = "User password must not be empty")
        String password,

        @NotEmpty(message = "User role must not be empty")
        String role
) {
}

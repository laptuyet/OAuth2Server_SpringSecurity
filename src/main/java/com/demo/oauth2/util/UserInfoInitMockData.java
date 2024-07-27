package com.demo.oauth2.util;

import com.demo.oauth2.entity.UserInfo;
import com.demo.oauth2.repo.UserInfoRepo;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@RequiredArgsConstructor
public class UserInfoInitMockData implements CommandLineRunner {
    private final UserInfoRepo userInfoRepo;
    private final PasswordEncoder passwordEncoder;

    private static final String DEFAULT_PASSWORD = "12345";

    @Override
    public void run(String... args) throws Exception {
        UserInfo manager = UserInfo.builder()
                .username("manager")
                .password(passwordEncoder.encode(DEFAULT_PASSWORD))
                .email("manager@gmail.com")
                .roles("ROLE_MANAGER")
                .build();

        UserInfo admin = UserInfo.builder()
                .username("admin")
                .password(passwordEncoder.encode(DEFAULT_PASSWORD))
                .email("admin@gmail.com")
                .roles("ROLE_ADMIN")
                .build();

        UserInfo user = UserInfo.builder()
                .username("user")
                .password(passwordEncoder.encode(DEFAULT_PASSWORD))
                .email("user@gmail.com")
                .roles("ROLE_USER")
                .build();

        userInfoRepo.saveAll(List.of(manager, admin, user));
    }
}

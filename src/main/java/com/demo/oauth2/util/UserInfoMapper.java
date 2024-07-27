package com.demo.oauth2.util;

import com.demo.oauth2.dto.UserRegistration;
import com.demo.oauth2.entity.UserInfo;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import java.util.function.Function;

@Component
@RequiredArgsConstructor
public class UserInfoMapper implements Function<UserRegistration, UserInfo> {

    private final PasswordEncoder passwordEncoder;

    @Override
    public UserInfo apply(UserRegistration userRegistration) {
        return UserInfo.builder()
                .username(userRegistration.username())
                .password(passwordEncoder.encode(userRegistration.password()))
                .email(userRegistration.email())
                .phone(userRegistration.phone())
                .roles(userRegistration.role())
                .build();
    }
}

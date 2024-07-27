package com.demo.oauth2.service;

import com.demo.oauth2.config.jwtConfig.JwtTokenGenerator;
import com.demo.oauth2.dto.AuthResponse;
import com.demo.oauth2.dto.TokenType;
import com.demo.oauth2.dto.UserRegistration;
import com.demo.oauth2.entity.RefreshTokenEntity;
import com.demo.oauth2.entity.UserInfo;
import com.demo.oauth2.repo.RefreshTokenRepo;
import com.demo.oauth2.repo.UserInfoRepo;
import com.demo.oauth2.util.UserInfoMapper;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
@Slf4j
public class AuthService {

    private final UserInfoRepo userInfoRepo;

    private final RefreshTokenRepo refreshTokenRepo;

    private final JwtTokenGenerator jwtTokenGenerator;

    private final UserInfoMapper userInfoMapper;

    public AuthResponse getJwtTokensAfterAuthentication(Authentication authentication, HttpServletResponse response) {
        try {
            var userInfoEntity = userInfoRepo.findByEmail(authentication.getName())
                    .orElseThrow(() -> {
                        log.error("[AuthService:userSignInAuth] User: {} not found", authentication.getName());
                        return new ResponseStatusException(HttpStatus.NOT_FOUND, "USER NOT FOUND ");
                    });

            String accessToken = jwtTokenGenerator.generateAccessToken(authentication);

            String refreshToken = jwtTokenGenerator.generateRefreshToken(authentication);

            saveUserRefreshToken(userInfoEntity, refreshToken);

            // Set refresh token to HTTP Only
            creatRefreshTokenCookie(response, refreshToken);

            log.info("[AuthService:userSignInAuth] Access token for user:{}, has been generated", userInfoEntity.getUsername());
            return AuthResponse.builder()
                    .accessToken(accessToken)
                    .accessTokenExpiry(2 * 60) // 2 mins
                    .userName(userInfoEntity.getUsername())
                    .tokenType(TokenType.Bearer)
                    .build();


        } catch (Exception e) {
            log.error("[AuthService:userSignInAuth]Exception while authenticating the user due to :" + e.getMessage());
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Please Try Again");
        }
    }

    public Object getAccessTokenUsingRefreshToken(String authHeader) {
        if (!authHeader.startsWith(TokenType.Bearer.name())) {
            return new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Refresh token revoked");
        }

        final String refreshToken = authHeader.substring(7);
        var refreshTokenEntity = refreshTokenRepo.findByRefreshToken(refreshToken)
                .filter(rt -> !rt.getRevoked())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "Refresh token revoked"));

        UserInfo user = refreshTokenEntity.getUser();

        //Now create the Authentication object
        Authentication authentication = createAuthenticationObject(user);

        //Use the authentication object to generate new accessToken as the Authentication object that we will have may not contain correct role.
        String accessToken = jwtTokenGenerator.generateAccessToken(authentication);

        return AuthResponse.builder()
                .accessToken(accessToken)
                .accessTokenExpiry(5 * 60)
                .userName(user.getUsername())
                .tokenType(TokenType.Bearer)
                .build();
    }

    public AuthResponse registerUser(UserRegistration userRegistration, HttpServletResponse httpServletResponse) {

        try {
            log.info("[AuthService:registerUser]User Registration Started with :::{}", userRegistration);

            Optional<UserInfo> user = userInfoRepo.findByEmail(userRegistration.email());
            if (user.isPresent()) {
                throw new Exception("User Already Exist");
            }

            UserInfo userDetailsEntity = userInfoMapper.apply(userRegistration);
            Authentication authentication = createAuthenticationObject(userDetailsEntity);


            // Generate a JWT token
            String accessToken = jwtTokenGenerator.generateAccessToken(authentication);
            String refreshToken = jwtTokenGenerator.generateRefreshToken(authentication);

            UserInfo savedUserDetails = userInfoRepo.save(userDetailsEntity);
            saveUserRefreshToken(userDetailsEntity, refreshToken);

            creatRefreshTokenCookie(httpServletResponse, refreshToken);

            log.info("[AuthService:registerUser] User:{} Successfully registered", savedUserDetails.getUsername());
            return AuthResponse.builder()
                    .accessToken(accessToken)
                    .accessTokenExpiry(5 * 60)
                    .userName(savedUserDetails.getUsername())
                    .tokenType(TokenType.Bearer)
                    .build();


        } catch (Exception e) {
            log.error("[AuthService:registerUser]Exception while registering the user due to :" + e.getMessage());
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST, e.getMessage());
        }

    }

    private void saveUserRefreshToken(UserInfo userInfo, String refreshToken) {
        RefreshTokenEntity refreshTokenEntity = RefreshTokenEntity.builder()
                .user(userInfo)
                .refreshToken(refreshToken)
                .revoked(false)
                .build();
        refreshTokenRepo.save(refreshTokenEntity);
    }

    private Cookie creatRefreshTokenCookie(HttpServletResponse resp, String refreshToken) {
        Cookie cookie = new Cookie("refresh_token", refreshToken);
        cookie.setHttpOnly(Boolean.TRUE);
        cookie.setSecure(Boolean.TRUE);
        cookie.setMaxAge(15 * 24 * 60 * 60); // in seconds
        resp.addCookie(cookie);
        return cookie;
    }

    private Authentication createAuthenticationObject(UserInfo user) {
        String roles = user.getRoles();
        List<GrantedAuthority> authorities = Arrays.stream(roles.split(","))
                .map(role -> new SimpleGrantedAuthority(role.trim()))
                .collect(Collectors.toList());
        return new UsernamePasswordAuthenticationToken(user.getEmail(), user.getPassword(), authorities);
    }
}

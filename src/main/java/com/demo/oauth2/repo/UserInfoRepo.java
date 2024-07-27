package com.demo.oauth2.repo;

import com.demo.oauth2.entity.UserInfo;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UserInfoRepo extends JpaRepository<UserInfo, Long> {

    Optional<UserInfo> findByEmail(String email);
}

package com.example.jwttest2;

import com.example.jwttest2.jwt.TokenInfo;
import com.example.jwttest2.jwt.UserService;
import com.example.jwttest2.redis.RefreshToken;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@Slf4j
public class TestController {
    @Autowired
    private UserService userService;

    @PostMapping("/login")
    public TokenInfo login(@RequestBody Map<String, Object> userInfo) {
        log.info("login start userInfo: {}", userInfo);
        String loginId = (String)userInfo.get("loginId");
        String password = (String)userInfo.get("password");
        return userService.login(loginId, password);
    }

    @PostMapping("/accessToken")
    public TokenInfo accessToken(@RequestBody RefreshToken refreshToken) {
        return TokenInfo.builder()
                .grantType("Bearer")
                .accessToken(userService.generateAccessToken(refreshToken.getRefreshToken()))
                .build();
    }

    @PostMapping("/test")
    public String test() {
        return "success";
    }

}

package com.example.jwttest2.jwt;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Service;

@Service
@Slf4j
public class UserService {
    @Autowired
    private AuthenticationManagerBuilder authenticationManagerBuilder;
    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    /**
     * 로그인
     * @param loginId 
     * @param password
     * @return
     */
    public TokenInfo login(String loginId, String password) {
        // Authentication 객체 생성
        UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(loginId, password);
        // authenticate 매서드가 실행될 때 CustomUserDetailsService 에서 만든 loadUserByUsername 메서드가 실행
        Authentication authentication = authenticationManagerBuilder.getObject().authenticate(authenticationToken);

        TokenInfo tokenInfo = jwtTokenProvider.generateToken(authentication);
        log.info("tokenInfo: {}", tokenInfo);
        return tokenInfo;
    }

    /**
     * refreshToken을 이용하여 accessToken 생성
     * @param refreshToken 
     * @return
     */
    public String generateAccessToken(String refreshToken) {
        return jwtTokenProvider.generateAccessToken(refreshToken);
    }
}

package com.example.jwttest2.redis;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.data.annotation.Id;
import org.springframework.data.redis.core.RedisHash;

@RedisHash(value = "refreshToken", timeToLive = 60 * 60 * 24 * 3)
@ToString
@Getter
@Setter
public class RefreshToken {

    @Id
    private String refreshToken;
    private String loginId;

    public RefreshToken(final String refreshToken, final String loginId) {
        this.refreshToken = refreshToken;
        this.loginId = loginId;
    }
}

package com.example.jwttest2.redis;

import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.stereotype.Repository;

import java.util.*;
import java.util.concurrent.TimeUnit;

@Repository
@Slf4j
public class RefreshTokenRepository {

    private final RedisTemplate<String, String> redisTemplate;

    public RefreshTokenRepository(final RedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    /**
     * loginId, refreshToken Redis에 저장
     * @param refreshToken
     */
    public void save(final RefreshToken refreshToken) {
        ValueOperations<String, String> valueOperations = redisTemplate.opsForValue();
        valueOperations.set(refreshToken.getLoginId(), refreshToken.getRefreshToken());
        redisTemplate.expire(refreshToken.getLoginId(), 3L, TimeUnit.DAYS);
    }

    /**
     * Key: loginId 로 Value: refreshToken 찾기
     * @param loginId
     * @return
     */
    // refreshToken으로 loginId 찾기
    public Optional<RefreshToken> findRefreshTokenByLoginId(final String loginId) {
        ValueOperations<String, String> valueOperations = redisTemplate.opsForValue();
        String refreshToken = valueOperations.get(loginId);

        if (Objects.isNull(refreshToken)) {
            return Optional.empty();
        }

        return Optional.of(new RefreshToken(refreshToken, loginId));
    }

    public void deleteRawByKey(String key) {
        redisTemplate.delete(key);
    }
}

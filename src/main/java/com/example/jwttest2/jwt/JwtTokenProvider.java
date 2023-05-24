package com.example.jwttest2.jwt;

import com.example.jwttest2.redis.RefreshToken;
import com.example.jwttest2.redis.RefreshTokenRepository;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
@Component
public class JwtTokenProvider {

    @Autowired
    RefreshTokenRepository refreshTokenRepository;

    private final Key key;
    private final Date refreshTokenExpiresIn = new Date((new Date()).getTime() + 60 * 60 * 24 * 3 * 1000); // 3일
    private final Date accessTokenExpiresIn = new Date((new Date()).getTime() + 60 * 15 * 1000); // 15분

    public JwtTokenProvider(@Value("${jwt.secret}") String secretKey) {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        this.key = Keys.hmacShaKeyFor(keyBytes);
    }

    /**
     * 로그인시 -> 유저 정보를 가지고 RefreshToken, AccessToken 생성하는 메서드
     * @param authentication
     * @return
     */
    public TokenInfo generateToken(Authentication authentication) {
        // 컬렉션 형태의 권한을 String.Join(,) 형태로 변경 - claim에 넣기위해
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        // 중복 제거는 필요하지않음. key를 덮어쓰기 때문
        /*refreshTokenRepository.findRefreshTokenByLoginId(authentication.getName())
                .ifPresent(originToken -> refreshTokenRepository.deleteRawByKey(originToken.getLoginId()));*/

        // Refresh Token 생성
        RefreshToken refreshToken = generateRefreshToken(authentication.getName(), authorities);

        // Access Token 생성
        // 최초 로그인 시점이므로 로그인한 시점에서 시큐리티에서 권한까지 조회하여 role까지 설정
        String accessToken = Jwts.builder()
                .setSubject("accessToken")
                .claim("auth", authorities)
                .setExpiration(accessTokenExpiresIn)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        return TokenInfo.builder()
                .grantType("Bearer")
                .accessToken(accessToken)
                .refreshToken(refreshToken.getRefreshToken())
                .build();
    }

    /**
     * JWT 토큰을 복호화하여 토큰에 들어있는 정보를 꺼내는 메서드
     * @param token
     * @return
     */
    public Authentication getAuthentication(String token) {
        // 토큰 복호화
        Claims claims = parseClaims(token);

        if (claims.get("auth") == null) {
            throw new RuntimeException("권한 정보가 없는 토큰입니다.");
        }

        if (parseSubject(token).equals("refreshToken") && claims.get("loginId") == null) {
            throw new RuntimeException("로그인 아이디가 없는 refresh토큰입니다.");
        }

        // String으로 변환한 Role정보를 컬렉션으로 변환하여 Role세팅
        Collection<? extends GrantedAuthority> authorities =
                Arrays.stream(claims.get("auth").toString().split(","))
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

        UserDetails principal = new User(claims.getSubject(), "", authorities);
        return new UsernamePasswordAuthenticationToken(principal, "", authorities);
    }

    /**
     * 토큰 유효성 검사
     * @param token 
     * @return
     */
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);
            return true;
        } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
            log.info("Invalid JWT Token", e);
            throw new RuntimeException("유효하지 않은 JWT 토큰입니다.");
        } catch (ExpiredJwtException e) {
            log.info("Expired JWT Token", e);
            throw new RuntimeException("Expired JWT Token");
        } catch (UnsupportedJwtException e) {
            log.info("Unsupported JWT Token", e);
        } catch (IllegalArgumentException e) {
            log.info("JWT claims string is empty.", e);
        }
        return false;
    }

    /**
     *  loginId와 권한으로 refreshToken 생성
     * @param loginId
     * @param authorities
     * @return
     */
    public RefreshToken generateRefreshToken(String loginId, String authorities) {
        // refresh 토큰생성이후 redis에 넣기
        String refreshTokenStr = Jwts.builder()
                .setSubject("refreshToken")
                .claim("auth", authorities)
                .claim("loginId", loginId)
                .setExpiration(refreshTokenExpiresIn)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        RefreshToken refreshToken = new RefreshToken(refreshTokenStr, loginId);
        // redis에 토큰 정보 넣기
        refreshTokenRepository.save(refreshToken);
        return refreshToken;
    }

    /**
     * refreshToken을 이용해서 엑세스토큰 생성하기
     * @param refreshTokenStr
     * @return
     */
    public String generateAccessToken(String refreshTokenStr) {
        // 레디스에 저장된 loginId, refreshToken 정보 가져오기
        Claims claims = parseClaims(refreshTokenStr);
        String loginId = (String) claims.get("loginId");
        Date expiredDate = claims.getExpiration();
        Date now = new Date();

        // 만료됬을때
        if(now.after(expiredDate)) {
            throw new RuntimeException("refresh 토큰이 만료되었습니다. 재로그인 해주세요.");
        }

        // redis에서 token 정보를 찾을수가 없을때
        refreshTokenRepository.findRefreshTokenByLoginId(loginId)
                .orElseThrow(() -> new RuntimeException("refresh 토큰이 만료되었습니다. 재로그인 해주세요."));

         /*
            claim 을 설정할수 있는 방법은 2가지
            1. setClaims을 통해 map 형식으로 넣기
            2. claim으로 Key, Value를 직접넣기
        */
        return Jwts.builder()
                .setSubject("accessToken")
                .claim("auth", claims.get("auth"))
                .setExpiration(accessTokenExpiresIn)
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }


    /**
     * token으로 claims 추출
     * @param token
     * @return
     */
    private Claims parseClaims(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(key)
                    .build()
                    .parseClaimsJws(token)
                    .getBody();
        } catch (ExpiredJwtException e) {
            return e.getClaims();
        }
    }

    /**
     * token으로 subject 추출
     * @param token
     * @return
     */
    public String parseSubject(final String token) {
        try {
            return parseClaims(token).getSubject();
        } catch (final JwtException e) {
            throw new RuntimeException("parseSubject error. 관리자에게 문의해주세요.");
        }
    }
}
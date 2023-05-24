package com.example.jwttest2.jwt;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.List;

@Service
@Slf4j
public class CustomUserDetailsService implements UserDetailsService {
    @Autowired
    PasswordEncoder passwordEncoder;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        if(username.equals("admin")) {
            CustomUser customUser = new CustomUser();
            customUser.setLoginId("admin");
            customUser.setPassword(passwordEncoder.encode("password"));
            List<String> roles = new ArrayList<>();
            roles.add("ROLE_USER");
            customUser.setRoles(roles);
            return customUser;
        } else {
            throw new UsernameNotFoundException("해당하는 유저를 찾을 수 없습니다.");
        }
    }
}

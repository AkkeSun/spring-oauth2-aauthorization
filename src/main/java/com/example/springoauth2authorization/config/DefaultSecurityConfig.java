package com.example.springoauth2authorization.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

/*
    사용자 인증을 위한 설정클래스
 */
@EnableWebSecurity
public class DefaultSecurityConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests().anyRequest().authenticated();

        // AuthenticationProvider 커스텀 클래스 사용시 필요한 설정
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setUserDetailsService(userDetailsService());
        http.authenticationProvider(daoAuthenticationProvider);

        // 인증받지 않은 사용자 접근시 form Login 창에서 인증받도록 설정
        http.formLogin();
        return http.build();
    }

    // 테스트를 위한 사용자 생성
    @Bean
    public UserDetailsService userDetailsService(){
        UserDetails userDetails = User.withUsername("user").password("{noop}1234").authorities("ROLE_USER").build();
        return new InMemoryUserDetailsManager(userDetails);
    }

}

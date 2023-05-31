package com.example.springoauth2authorization.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

/*
    인가서버 설정
 */
@Configuration
public class AuthorizationServerConfig {

    @Bean
    public SecurityFilterChain authSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        // 미인증시 /login 페이지 이동
        http.exceptionHandling(e -> e.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")));
        // access token 검증 API
        http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
        return http.build();
    }
}

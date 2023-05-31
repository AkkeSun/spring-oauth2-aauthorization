package com.example.springoauth2authorization.config;

import com.example.springoauth2authorization.handler.CustomAuthenticationFailureHandler;
import com.example.springoauth2authorization.handler.CustomAuthenticationSuccessHandler;
import com.example.springoauth2authorization.provider.CustomAuthenticationProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.authorization.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.RequestMatcher;

/*
    인가서버 설정
 */
@Configuration
@RequiredArgsConstructor
public class AuthorizationServerConfig {

    private final CustomAuthenticationProvider authenticationProvider;
    private final CustomAuthenticationSuccessHandler authenticationSuccessHandler;
    private final CustomAuthenticationFailureHandler authenticationFailureHandler;

    @Bean
    public SecurityFilterChain authSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer<HttpSecurity> auth2AuthorizationServerConfigurer =
            new OAuth2AuthorizationServerConfigurer<>();
        RequestMatcher endpointMather = auth2AuthorizationServerConfigurer
            .getEndpointsMatcher();

        auth2AuthorizationServerConfigurer.authorizationEndpoint(
            endpoint -> endpoint
                .authorizationResponseHandler(authenticationSuccessHandler)
                .errorResponseHandler(authenticationFailureHandler)
                .authenticationProvider(authenticationProvider)
        );

        http
            .requestMatcher(endpointMather)
            .authorizeRequests(authorizationRequests ->
                authorizationRequests.anyRequest().authenticated()
            )
            .csrf(csrf -> csrf.ignoringRequestMatchers(endpointMather))
            .apply(auth2AuthorizationServerConfigurer);

        // 단순 설정시 사용
        // OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
        // 미인증시 /login 페이지 이동
        http.exceptionHandling(e -> e.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")));
        // access token 검증 API
        http.oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt);
        return http.build();
    }
}

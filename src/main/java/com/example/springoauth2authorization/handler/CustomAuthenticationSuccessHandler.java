package com.example.springoauth2authorization.handler;

import java.io.IOException;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeRequestAuthenticationToken;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

@Component
public class CustomAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
        Authentication authentication) throws IOException, ServletException {
        OAuth2AuthorizationCodeRequestAuthenticationToken authentication1 = (OAuth2AuthorizationCodeRequestAuthenticationToken) authentication;
        System.out.println(authentication);
        String redirectUri = authentication1.getRedirectUri();
        String authorizationCode = authentication1.getAuthorizationCode().getTokenValue();
        String state = null;
        if (StringUtils.hasText(authentication1.getState())) {
            state = authentication1.getState();
        }
        response.sendRedirect(redirectUri+"?code="+authorizationCode+"&state="+state);
    }
}

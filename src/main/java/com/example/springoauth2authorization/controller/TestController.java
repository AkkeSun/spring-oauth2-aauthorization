package com.example.springoauth2authorization.controller;

import java.util.Arrays;
import java.util.List;
import lombok.RequiredArgsConstructor;
import org.springframework.security.oauth2.core.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequiredArgsConstructor
public class TestController {

    private final RegisteredClientRepository registeredClientRepository;
    private final OAuth2AuthorizationService oAuth2AuthorizationService;

    @GetMapping("/registeredClients")
    public List<RegisteredClient> getRegisteredClient(){
        RegisteredClient client1 = registeredClientRepository.findByClientId("oauth2-client-app1");
        RegisteredClient client2 = registeredClientRepository.findByClientId("oauth2-client-app2");
        RegisteredClient client3 = registeredClientRepository.findByClientId("oauth2-client-app3");
        return Arrays.asList(client1, client2, client3);
    }

    @GetMapping("/checkToken")
    public OAuth2Authorization getToken(String tokenStr){
        return oAuth2AuthorizationService.findByToken(tokenStr, OAuth2TokenType.ACCESS_TOKEN);
    }
}

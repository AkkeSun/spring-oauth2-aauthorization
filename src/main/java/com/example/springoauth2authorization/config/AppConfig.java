package com.example.springoauth2authorization.config;

import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.UUID;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.ClientSettings;
import org.springframework.security.oauth2.server.authorization.config.ProviderSettings;
import org.springframework.security.oauth2.server.authorization.config.TokenSettings;

@Configuration
public class AppConfig {

    @Bean
    public ProviderSettings providerSettings(){
        // provider 디폴트 설정
        return ProviderSettings.builder().issuer("http://localhost:9000").build();
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
        // 클라이언트 등록
        RegisteredClient client1 =
            getRegisteredClient("oauth2-client-app1", "{noop}secret1", "read", "write");
        RegisteredClient client2 =
            getRegisteredClient("oauth2-client-app2", "{noop}secret2", "read", "delete");
        RegisteredClient client3 =
            getRegisteredClient("oauth2-client-app3", "{noop}secret3", "read", "update");
        return new InMemoryRegisteredClientRepository(Arrays.asList(client1, client2, client3));
    }

    @Bean
    public OAuth2AuthorizationService oAuth2AuthorizationService() {
        // 클라이언트의 인가 상태를 관리하는 서비스. InMemory 방식과 JDBC 방식이 있다
        return new InMemoryOAuth2AuthorizationService();
    }

    private RegisteredClient getRegisteredClient(String clientId, String clientSecret, String scope1, String scope2){
        return RegisteredClient
            .withId(UUID.randomUUID().toString())
            .clientId(clientId)
            .clientSecret(clientSecret)
            .clientName(clientId)
            // 생성일
            .clientIdIssuedAt(Instant.now())
            // 만료기간
            .clientSecretExpiresAt(Instant.MAX)
            // 인증 방법
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
            .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
            // 권한부여 유형 (password 방식은 미지원)
            .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
            .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .redirectUri("http://127.0.0.1:8081")
            .scope(OidcScopes.OPENID)
            .scope(OidcScopes.PROFILE)
            .scope(OidcScopes.EMAIL)
            .scope(scope1)
            .scope(scope2)
            // 사용자 동의 과정 사용 유무
            .clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build())
            // 토큰설정
            .tokenSettings(TokenSettings.builder().accessTokenTimeToLive(Duration.ofMinutes(11)).build())
            .build();
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource){
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() throws NoSuchAlgorithmException {
        RSAKey rsakey = generateRsa();
        JWKSet jwkSet = new JWKSet(rsakey);
        return (jwtSelector, context) -> jwtSelector.select(jwkSet);
    }

    @Bean
    public OAuth2AuthorizationConsentService oAuth2AuthorizationConsentService(){
        return new InMemoryOAuth2AuthorizationConsentService();
    }

    private RSAKey generateRsa() throws NoSuchAlgorithmException {
        KeyPair keyPair = generateRsaKey();
        RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        return new RSAKey.Builder(publicKey)
            .privateKey(privateKey)
            .keyID(UUID.randomUUID().toString())
            .build();
    }

    private KeyPair generateRsaKey() throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048);
        return keyPairGenerator.generateKeyPair();
    }

}

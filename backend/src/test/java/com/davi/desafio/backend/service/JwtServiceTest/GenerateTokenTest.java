package com.davi.desafio.backend.service.JwtServiceTest;

import static org.junit.jupiter.api.Assertions.*;

import java.util.Date;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import com.davi.desafio.backend.service.impl.JwtService;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

/**
 * Classe de testes específica para o método generateToken do JwtService.
 * Testa diferentes cenários de geração de tokens JWT.
 */
@ExtendWith(MockitoExtension.class)
class GenerateTokenTest {

  @InjectMocks
  private JwtService jwtService;

  private static final String SECRET_KEY = "chaveSecretaParaTestes123456789chaveSecretaParaTestes123456789";
  private static final Long EXPIRATION_TIME = 3600000L; // 1 hora em milissegundos

  @BeforeEach
  void setUp() {
    ReflectionTestUtils.setField(jwtService, "jwtSecret", SECRET_KEY);
    ReflectionTestUtils.setField(jwtService, "jwtExpiration", EXPIRATION_TIME);
  }

  @Test
  @DisplayName("Deve gerar um token JWT válido com ID numérico")
  void generateToken_ShouldGenerateValidTokenWithNumericId() {
    // Arrange
    String userId = "123";

    // Act
    String token = jwtService.generateToken(userId);

    // Assert
    assertNotNull(token);
    assertTrue(token.split("\\.").length == 3); // Verifica se o token tem as 3 partes (header.payload.signature)
  }

  @Test
  @DisplayName("Deve gerar um token JWT válido com ID alfanumérico")
  void generateToken_ShouldGenerateValidTokenWithAlphanumericId() {
    // Arrange
    String userId = "user123";

    // Act
    String token = jwtService.generateToken(userId);

    // Assert
    assertNotNull(token);
    assertTrue(token.split("\\.").length == 3);
  }

  @Test
  @DisplayName("Deve gerar tokens diferentes para IDs diferentes")
  void generateToken_ShouldGenerateDifferentTokensForDifferentIds() {
    // Arrange
    String userId1 = "user1";
    String userId2 = "user2";

    // Act
    String token1 = jwtService.generateToken(userId1);
    String token2 = jwtService.generateToken(userId2);

    // Assert
    assertNotNull(token1);
    assertNotNull(token2);
    assertNotEquals(token1, token2);
  }

  @Test
  @DisplayName("Deve gerar token com tempo de expiração correto")
  void generateToken_ShouldGenerateTokenWithCorrectExpiration() {
    // Arrange
    String userId = "testUser";

    // Act
    String token = jwtService.generateToken(userId);

    // Assert
    assertNotNull(token);

    // Decodifica o token para verificar o tempo de expiração
    Claims claims = Jwts.parser()
        .verifyWith(Keys.hmacShaKeyFor(SECRET_KEY.getBytes()))
        .build()
        .parseSignedClaims(token)
        .getPayload();

    Date actualExpiration = claims.getExpiration();
    Date issuedAt = claims.getIssuedAt();

    // Verifica se o tempo de expiração é igual ao tempo de emissão + tempo de
    // expiração configurado
    assertEquals(EXPIRATION_TIME, actualExpiration.getTime() - issuedAt.getTime());
  }

  @Test
  @DisplayName("Deve gerar token válido com ID vazio")
  void generateToken_ShouldGenerateValidTokenWithEmptyId() {
    // Arrange
    String userId = "";

    // Act
    String token = jwtService.generateToken(userId);

    // Assert
    assertNotNull(token);
    assertTrue(token.split("\\.").length == 3);
  }
}

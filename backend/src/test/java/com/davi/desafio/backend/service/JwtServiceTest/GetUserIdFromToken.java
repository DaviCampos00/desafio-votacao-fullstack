package com.davi.desafio.backend.service.JwtServiceTest;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.util.Date;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import com.davi.desafio.backend.constants.jwt.JwtErrorMessages;
import com.davi.desafio.backend.exceptions.JwtAuthenticationException;
import com.davi.desafio.backend.service.impl.JwtService;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

/**
 * Classe de testes específica para o método getUserIdFromToken do JwtService.
 * Testa diferentes cenários de extração de ID do usuário de tokens JWT.
 */
@ExtendWith(MockitoExtension.class)
class GetUserIdFromToken {

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
  @DisplayName("Deve retornar o ID do usuário para token válido")
  void getUserIdFromToken_ShouldReturnUserIdForValidToken() throws JwtAuthenticationException {
    // Arrange
    String expectedUserId = "12345";
    String validToken = jwtService.generateToken(expectedUserId);

    // Act
    String actualUserId = jwtService.getUserIdFromToken(validToken);

    // Assert
    assertNotNull(actualUserId);
    assertEquals(expectedUserId, actualUserId);
  }

  @Test
  @DisplayName("Deve retornar o ID correto para diferentes usuários")
  void getUserIdFromToken_ShouldReturnCorrectIdForDifferentUsers() throws JwtAuthenticationException {
    // Arrange
    String userId1 = "user123";
    String userId2 = "admin456";
    String token1 = jwtService.generateToken(userId1);
    String token2 = jwtService.generateToken(userId2);

    // Act
    String actualUserId1 = jwtService.getUserIdFromToken(token1);
    String actualUserId2 = jwtService.getUserIdFromToken(token2);

    // Assert
    assertEquals(userId1, actualUserId1);
    assertEquals(userId2, actualUserId2);
    assertNotEquals(actualUserId1, actualUserId2);
  }

  @Test
  @DisplayName("Deve lançar exceção para token malformado")
  void getUserIdFromToken_ShouldThrowExceptionForMalformedToken() {
    // Arrange
    String malformedToken = "token.malformado.invalido";

    // Act & Assert
    JwtAuthenticationException exception = assertThrows(JwtAuthenticationException.class,
        () -> jwtService.getUserIdFromToken(malformedToken));

    assertEquals(JwtErrorMessages.JWT_TOKEN_MALFORMED.getMessage(), exception.getJwtErrorMessages());
  }

  @Test
  @DisplayName("Deve lançar exceção para token expirado")
  void getUserIdFromToken_ShouldThrowExceptionForExpiredToken() {
    // Arrange
    Date pastDate = new Date(System.currentTimeMillis() - 3600000); // 1 hora atrás
    Date expiredDate = new Date(System.currentTimeMillis() - 1800000); // 30 minutos atrás

    String expiredToken = Jwts.builder()
        .subject("123")
        .issuedAt(pastDate)
        .expiration(expiredDate)
        .signWith(Keys.hmacShaKeyFor(SECRET_KEY.getBytes()))
        .compact();

    // Act & Assert
    JwtAuthenticationException exception = assertThrows(JwtAuthenticationException.class,
        () -> jwtService.getUserIdFromToken(expiredToken));

    assertEquals(JwtErrorMessages.JWT_TOKEN_EXPIRED.getMessage(), exception.getJwtErrorMessages());
  }

  @Test
  @DisplayName("Deve lançar exceção para token com argumento ilegal")
  void getUserIdFromToken_ShouldThrowExceptionForIllegalArgumentToken() {
    // Arrange
    String nullToken = null;

    // Act & Assert
    JwtAuthenticationException exception = assertThrows(JwtAuthenticationException.class,
        () -> jwtService.getUserIdFromToken(nullToken));

    assertEquals(JwtErrorMessages.JWT_TOKEN_ILLEGAL_ARGUMENT.getMessage(), exception.getJwtErrorMessages());
  }

  @Test
  @DisplayName("Deve lançar exceção para token vazio")
  void getUserIdFromToken_ShouldThrowExceptionForEmptyToken() {
    // Arrange
    String emptyToken = "";

    // Act & Assert
    JwtAuthenticationException exception = assertThrows(JwtAuthenticationException.class,
        () -> jwtService.getUserIdFromToken(emptyToken));

    assertEquals(JwtErrorMessages.JWT_TOKEN_ILLEGAL_ARGUMENT.getMessage(), exception.getJwtErrorMessages());
  }

  @Test
  @DisplayName("Deve lançar exceção para token não suportado")
  void getUserIdFromToken_ShouldThrowExceptionForUnsupportedToken() {
    // Arrange
    // Criando um token JWT sem assinatura (unsupported)
    String unsupportedToken = Jwts.builder()
        .subject("123")
        .issuedAt(new Date())
        .expiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
        .compact(); // Token sem assinatura

    // Act & Assert
    JwtAuthenticationException exception = assertThrows(JwtAuthenticationException.class,
        () -> jwtService.getUserIdFromToken(unsupportedToken));

    assertEquals(JwtErrorMessages.JWT_TOKEN_UNSUPPORTED.getMessage(), exception.getJwtErrorMessages());
  }

  @Test
  @DisplayName("Deve lançar exceção genérica para erro não específico")
  void getUserIdFromToken_ShouldThrowGenericExceptionForUnknownError() {
    // Arrange
    String tokenWithWrongSignature = Jwts.builder()
        .subject("123")
        .issuedAt(new Date())
        .expiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
        .signWith(Keys.hmacShaKeyFor("chaveErrada12345678901234567890123456789012345678901234567890".getBytes()))
        .compact();

    // Act & Assert
    JwtAuthenticationException exception = assertThrows(JwtAuthenticationException.class,
        () -> jwtService.getUserIdFromToken(tokenWithWrongSignature));

    assertEquals(JwtErrorMessages.JWT_AUTHENTICATION_ERROR.getMessage(), exception.getJwtErrorMessages());
  }

  @Test
  @DisplayName("Deve extrair ID do usuário corretamente sem chamar múltiplas vezes")
  void getUserIdFromToken_ShouldExtractUserIdOnlyOnce() throws JwtAuthenticationException {
    // Arrange
    String expectedUserId = "testUser789";
    String validToken = jwtService.generateToken(expectedUserId);

    // Criando um spy do JwtService para verificar quantas vezes o método é chamado
    JwtService spyJwtService = spy(jwtService);

    // Act
    String actualUserId = spyJwtService.getUserIdFromToken(validToken);

    // Assert
    assertEquals(expectedUserId, actualUserId);
    // Verificando que o método getUserIdFromToken foi chamado exatamente uma vez
    verify(spyJwtService, times(1)).getUserIdFromToken(validToken);
  }

  @Test
  @DisplayName("Deve retornar null quando token foi gerado com ID vazio")
  void getUserIdFromToken_ShouldReturnNullWhenTokenGeneratedWithEmptyId() throws JwtAuthenticationException {
    // Arrange
    String emptyUserId = "";
    String validToken = jwtService.generateToken(emptyUserId);

    // Act
    String actualUserId = jwtService.getUserIdFromToken(validToken);

    // Assert
    // JWT armazena string vazia como null no subject
    assertNull(actualUserId);
  }

  @Test
  @DisplayName("Deve retornar ID alfanumérico corretamente")
  void getUserIdFromToken_ShouldReturnAlphanumericIdCorrectly() throws JwtAuthenticationException {
    // Arrange
    String alphanumericUserId = "user_123_admin";
    String validToken = jwtService.generateToken(alphanumericUserId);

    // Act
    String actualUserId = jwtService.getUserIdFromToken(validToken);

    // Assert
    assertEquals(alphanumericUserId, actualUserId);
  }
}

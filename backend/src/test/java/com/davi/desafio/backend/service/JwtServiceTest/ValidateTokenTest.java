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
 * Classe de testes específica para o método validateToken do JwtService.
 * Testa diferentes cenários de validação de tokens JWT.
 */
@ExtendWith(MockitoExtension.class)
class ValidateTokenTest {

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
  @DisplayName("Deve retornar true para token válido")
  void validateToken_ShouldReturnTrueForValidToken() throws JwtAuthenticationException {
    // Arrange
    String userId = "123";
    String validToken = jwtService.generateToken(userId);

    // Act
    boolean result = jwtService.validateToken(validToken);

    // Assert
    assertTrue(result);
  }

  @Test
  @DisplayName("Deve lançar exceção para token malformado")
  void validateToken_ShouldThrowExceptionForMalformedToken() {
    // Arrange
    String malformedToken = "token.malformado.invalido";

    // Act & Assert
    JwtAuthenticationException exception = assertThrows(JwtAuthenticationException.class,
        () -> jwtService.validateToken(malformedToken));

    assertEquals(JwtErrorMessages.JWT_TOKEN_MALFORMED.getMessage(), exception.getJwtErrorMessages());
  }

  @Test
  @DisplayName("Deve lançar exceção para token expirado")
  void validateToken_ShouldThrowExceptionForExpiredToken() {
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
        () -> jwtService.validateToken(expiredToken));

    assertEquals(JwtErrorMessages.JWT_TOKEN_EXPIRED.getMessage(), exception.getJwtErrorMessages());
  }

  @Test
  @DisplayName("Deve lançar exceção para token com argumento ilegal")
  void validateToken_ShouldThrowExceptionForIllegalArgumentToken() {
    // Arrange
    String nullToken = null;

    // Act & Assert
    JwtAuthenticationException exception = assertThrows(JwtAuthenticationException.class,
        () -> jwtService.validateToken(nullToken));

    assertEquals(JwtErrorMessages.JWT_TOKEN_ILLEGAL_ARGUMENT.getMessage(), exception.getJwtErrorMessages());
  }

  @Test
  @DisplayName("Deve lançar exceção para token vazio")
  void validateToken_ShouldThrowExceptionForEmptyToken() {
    // Arrange
    String emptyToken = "";

    // Act & Assert
    JwtAuthenticationException exception = assertThrows(JwtAuthenticationException.class,
        () -> jwtService.validateToken(emptyToken));

    assertEquals(JwtErrorMessages.JWT_TOKEN_ILLEGAL_ARGUMENT.getMessage(), exception.getJwtErrorMessages());
  }

  @Test
  @DisplayName("Deve lançar exceção para token não suportado")
  void validateToken_ShouldThrowExceptionForUnsupportedToken() {
    // Arrange
    // Criando um token JWT sem assinatura (unsupported)
    String unsupportedToken = Jwts.builder()
        .subject("123")
        .issuedAt(new Date())
        .expiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
        .compact(); // Token sem assinatura

    // Act & Assert
    JwtAuthenticationException exception = assertThrows(JwtAuthenticationException.class,
        () -> jwtService.validateToken(unsupportedToken));

    assertEquals(JwtErrorMessages.JWT_TOKEN_UNSUPPORTED.getMessage(), exception.getJwtErrorMessages());
  }

  @Test
  @DisplayName("Deve lançar exceção genérica para erro não específico")
  void validateToken_ShouldThrowGenericExceptionForUnknownError() {
    // Arrange
    String tokenWithWrongSignature = Jwts.builder()
        .subject("123")
        .issuedAt(new Date())
        .expiration(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
        .signWith(Keys.hmacShaKeyFor("chaveErrada12345678901234567890123456789012345678901234567890".getBytes()))
        .compact();

    // Act & Assert
    JwtAuthenticationException exception = assertThrows(JwtAuthenticationException.class,
        () -> jwtService.validateToken(tokenWithWrongSignature));

    assertEquals(JwtErrorMessages.JWT_AUTHENTICATION_ERROR.getMessage(), exception.getJwtErrorMessages());
  }

  @Test
  @DisplayName("Deve validar token corretamente sem chamar múltiplas vezes")
  void validateToken_ShouldValidateTokenOnlyOnce() throws JwtAuthenticationException {
    // Arrange
    String userId = "456";
    String validToken = jwtService.generateToken(userId);

    // Criando um spy do JwtService para verificar quantas vezes o método é chamado
    JwtService spyJwtService = spy(jwtService);

    // Act
    boolean result = spyJwtService.validateToken(validToken);

    // Assert
    assertTrue(result);
    // Verificando que o método validateToken foi chamado exatamente uma vez
    verify(spyJwtService, times(1)).validateToken(validToken);
  }

}

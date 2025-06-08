package com.davi.desafio.backend.service.JwtServiceTest;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import com.davi.desafio.backend.service.impl.JwtService;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Classe de testes específica para o método extractToken do JwtService.
 * Testa diferentes cenários de extração de tokens JWT do header da requisição.
 */
@ExtendWith(MockitoExtension.class)
class ExtractTokenTest {

  @InjectMocks
  private JwtService jwtService;

  @Mock
  private HttpServletRequest request;

  private static final String SECRET_KEY = "chaveSecretaParaTestes123456789chaveSecretaParaTestes123456789";
  private static final Long EXPIRATION_TIME = 3600000L; // 1 hora em milissegundos

  @BeforeEach
  void setUp() {
    ReflectionTestUtils.setField(jwtService, "jwtSecret", SECRET_KEY);
    ReflectionTestUtils.setField(jwtService, "jwtExpiration", EXPIRATION_TIME);
  }

  @Test
  @DisplayName("Deve extrair token quando header contém Bearer token válido")
  void extractToken_ShouldExtractTokenWhenValidBearerToken() {
    // Arrange
    String expectedToken = "valid.token.here";
    when(request.getHeader("Authorization")).thenReturn("Bearer " + expectedToken);

    // Act
    Optional<String> result = jwtService.extractToken(request);

    // Assert
    assertTrue(result.isPresent());
    assertEquals(expectedToken, result.get());
    // Verifica se o método getHeader foi chamado exatamente uma vez
    verify(request, times(1)).getHeader("Authorization");
  }

  @Test
  @DisplayName("Deve retornar Optional vazio quando header é nulo")
  void extractToken_ShouldReturnEmptyWhenHeaderIsNull() {
    // Arrange
    when(request.getHeader("Authorization")).thenReturn(null);

    // Act
    Optional<String> result = jwtService.extractToken(request);

    // Assert
    assertTrue(result.isEmpty());
    // Verifica se o método getHeader foi chamado exatamente uma vez
    verify(request, times(1)).getHeader("Authorization");
  }

  @Test
  @DisplayName("Deve retornar Optional vazio quando header não começa com Bearer")
  void extractToken_ShouldReturnEmptyWhenHeaderDoesNotStartWithBearer() {
    // Arrange
    when(request.getHeader("Authorization")).thenReturn("Invalid " + "token.here");

    // Act
    Optional<String> result = jwtService.extractToken(request);

    // Assert
    assertTrue(result.isEmpty());
    // Verifica se o método getHeader foi chamado exatamente uma vez
    verify(request, times(1)).getHeader("Authorization");
  }

  @Test
  @DisplayName("Deve retornar Optional vazio quando header está vazio")
  void extractToken_ShouldReturnEmptyWhenHeaderIsEmpty() {
    // Arrange
    when(request.getHeader("Authorization")).thenReturn("");

    // Act
    Optional<String> result = jwtService.extractToken(request);

    // Assert
    assertTrue(result.isEmpty());
    // Verifica se o método getHeader foi chamado exatamente uma vez
    verify(request, times(1)).getHeader("Authorization");
  }

}

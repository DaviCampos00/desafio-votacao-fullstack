package com.davi.desafio.backend.config;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

import java.io.IOException;
import java.util.Optional;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import com.davi.desafio.backend.constants.jwt.JwtErrorMessages;
import com.davi.desafio.backend.exceptions.JwtAuthenticationException;
import com.davi.desafio.backend.service.impl.JwtService;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Classe de testes específica para o JwtAuthenticationFilter.
 * Testa diferentes cenários de filtragem de autenticação JWT.
 */
@ExtendWith(MockitoExtension.class)
class JwtAuthenticationFilterJavaTest {

  @InjectMocks
  private JwtAuthenticationFilter jwtAuthenticationFilter;

  @Mock
  private JwtService jwtService;

  @Mock
  private HttpServletRequest request;

  @Mock
  private HttpServletResponse response;

  @Mock
  private FilterChain filterChain;

  @BeforeEach
  void setUp() {
    // Limpa o contexto de segurança antes de cada teste
    SecurityContextHolder.clearContext();
  }

  @Test
  @DisplayName("Deve permitir acesso a rota pública sem autenticação")
  void doFilterInternal_ShouldAllowPublicRouteWithoutAuthentication() throws ServletException, IOException {
    // Arrange
    when(request.getRequestURI()).thenReturn("/api/v1/health-check");

    // Act
    jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

    // Assert
    verify(filterChain, times(1)).doFilter(request, response);
    verify(jwtService, never()).extractToken(any());
    verify(jwtService, never()).validateToken(any());
    verify(jwtService, never()).getUserIdFromToken(any());
    assertNull(SecurityContextHolder.getContext().getAuthentication());
  }

  @Test
  @DisplayName("Deve lançar exceção quando token não é encontrado em rota privada")
  void doFilterInternal_ShouldThrowExceptionWhenTokenNotFoundInPrivateRoute() throws ServletException, IOException {
    // Arrange
    when(request.getRequestURI()).thenReturn("/api/v1/private-route");
    when(jwtService.extractToken(request)).thenReturn(Optional.empty());

    // Act & Assert
    JwtAuthenticationException exception = assertThrows(JwtAuthenticationException.class,
        () -> jwtAuthenticationFilter.doFilterInternal(request, response, filterChain));

    assertEquals(JwtErrorMessages.JWT_TOKEN_NOT_FOUND.getMessage(), exception.getJwtErrorMessages());
    verify(jwtService, times(1)).extractToken(request);
    verify(jwtService, never()).validateToken(any());
    verify(jwtService, never()).getUserIdFromToken(any());
    verify(filterChain, never()).doFilter(request, response);
    assertNull(SecurityContextHolder.getContext().getAuthentication());
  }

  @Test
  @DisplayName("Deve autenticar e continuar quando token é válido em rota privada")
  void doFilterInternal_ShouldAuthenticateAndContinueWhenValidTokenInPrivateRoute()
      throws ServletException, IOException, JwtAuthenticationException {
    // Arrange
    String validToken = "valid.jwt.token";
    String userId = "user123";
    when(request.getRequestURI()).thenReturn("/api/v1/private-route");
    when(jwtService.extractToken(request)).thenReturn(Optional.of(validToken));
    when(jwtService.validateToken(validToken)).thenReturn(true);
    when(jwtService.getUserIdFromToken(validToken)).thenReturn(userId);

    // Act
    jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

    // Assert
    verify(jwtService, times(1)).extractToken(request);
    verify(jwtService, times(1)).validateToken(validToken);
    verify(jwtService, times(1)).getUserIdFromToken(validToken);
    verify(filterChain, times(1)).doFilter(request, response);

    // Verifica se a autenticação foi definida no contexto
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    assertNotNull(authentication);
    assertEquals(userId, authentication.getPrincipal());
  }

  @Test
  @DisplayName("Deve lançar exceção quando token é inválido em rota privada")
  void doFilterInternal_ShouldThrowExceptionWhenInvalidTokenInPrivateRoute()
      throws JwtAuthenticationException, ServletException, IOException {
    // Arrange
    String invalidToken = "invalid.jwt.token";
    when(request.getRequestURI()).thenReturn("/api/v1/private-route");
    when(jwtService.extractToken(request)).thenReturn(Optional.of(invalidToken));
    when(jwtService.validateToken(invalidToken)).thenThrow(
        new JwtAuthenticationException(
            JwtErrorMessages.JWT_TOKEN_MALFORMED.getMessage(),
            "Token malformado"));

    // Act & Assert
    JwtAuthenticationException exception = assertThrows(JwtAuthenticationException.class,
        () -> jwtAuthenticationFilter.doFilterInternal(request, response, filterChain));

    assertEquals(JwtErrorMessages.JWT_TOKEN_MALFORMED.getMessage(), exception.getJwtErrorMessages());
    verify(jwtService, times(1)).extractToken(request);
    verify(jwtService, times(1)).validateToken(invalidToken);
    verify(jwtService, never()).getUserIdFromToken(any());
    verify(filterChain, never()).doFilter(request, response);
    assertNull(SecurityContextHolder.getContext().getAuthentication());
  }

  @Test
  @DisplayName("Deve lançar exceção quando getUserIdFromToken falha")
  void doFilterInternal_ShouldThrowExceptionWhenGetUserIdFromTokenFails()
      throws JwtAuthenticationException, ServletException, IOException {
    // Arrange
    String validToken = "valid.jwt.token";
    when(request.getRequestURI()).thenReturn("/api/v1/private-route");
    when(jwtService.extractToken(request)).thenReturn(Optional.of(validToken));
    when(jwtService.validateToken(validToken)).thenReturn(true);
    when(jwtService.getUserIdFromToken(validToken)).thenThrow(
        new JwtAuthenticationException(
            JwtErrorMessages.JWT_AUTHENTICATION_ERROR.getMessage(),
            "Erro ao extrair ID"));

    // Act & Assert
    JwtAuthenticationException exception = assertThrows(JwtAuthenticationException.class,
        () -> jwtAuthenticationFilter.doFilterInternal(request, response, filterChain));

    assertEquals(JwtErrorMessages.JWT_AUTHENTICATION_ERROR.getMessage(), exception.getJwtErrorMessages());
    verify(jwtService, times(1)).extractToken(request);
    verify(jwtService, times(1)).validateToken(validToken);
    verify(jwtService, times(1)).getUserIdFromToken(validToken);
    verify(filterChain, never()).doFilter(request, response);
    assertNull(SecurityContextHolder.getContext().getAuthentication());
  }

  @Test
  @DisplayName("Deve verificar se as rotas públicas são identificadas corretamente")
  void isRoutePublic_ShouldIdentifyPublicRoutesCorrectly() throws ServletException, IOException {
    // Arrange & Act & Assert - Health Check
    when(request.getRequestURI()).thenReturn("/api/v1/health-check");
    jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);
    verify(filterChain, times(1)).doFilter(request, response);

    // Reset mocks
    reset(filterChain);

    // Arrange & Act & Assert - Swagger UI
    when(request.getRequestURI()).thenReturn("/api/v1/swagger-ui/docs");
    jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);
    verify(filterChain, times(1)).doFilter(request, response);
  }

  @Test
  @DisplayName("Deve processar rota privada com token válido apenas uma vez")
  void doFilterInternal_ShouldProcessPrivateRouteWithValidTokenOnlyOnce()
      throws ServletException, IOException, JwtAuthenticationException {
    // Arrange
    String validToken = "valid.jwt.token";
    String userId = "user456";
    when(request.getRequestURI()).thenReturn("/api/v1/users");
    when(jwtService.extractToken(request)).thenReturn(Optional.of(validToken));
    when(jwtService.validateToken(validToken)).thenReturn(true);
    when(jwtService.getUserIdFromToken(validToken)).thenReturn(userId);

    // Act
    jwtAuthenticationFilter.doFilterInternal(request, response, filterChain);

    // Assert - Verifica que cada método foi chamado exatamente uma vez
    verify(jwtService, times(1)).extractToken(request);
    verify(jwtService, times(1)).validateToken(validToken);
    verify(jwtService, times(1)).getUserIdFromToken(validToken);
    verify(filterChain, times(1)).doFilter(request, response);

    // Verifica se a autenticação foi definida corretamente
    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
    assertNotNull(authentication);
    assertEquals(userId, authentication.getPrincipal());
    assertTrue(authentication.getAuthorities().isEmpty());
  }
}

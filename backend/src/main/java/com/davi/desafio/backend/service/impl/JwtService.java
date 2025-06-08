package com.davi.desafio.backend.service.impl;

import java.util.Date;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Value;

import org.springframework.stereotype.Service;

import com.davi.desafio.backend.constants.jwt.JwtErrorMessages;
import com.davi.desafio.backend.exceptions.JwtAuthenticationException;
import com.davi.desafio.backend.service.contracts.IJwtService;

import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;

/**
 * Serviço responsável pela geração e manipulação de tokens JWT.
 * Utiliza uma chave secreta configurável para assinar os tokens.
 */
@Service
public class JwtService implements IJwtService {

  @Value("${jwt.secret}")
  private String jwtSecret;

  @Value("${jwt.expiration}")
  private Long jwtExpiration;

  /**
   * Gera um token JWT contendo o ID do usuário.
   * 
   * @param id o identificador único do usuário que será incluído no token
   * @return uma string contendo o token JWT assinado com a chave secreta
   */
  public String generateToken(String id) {
    /* Data atual */
    Date now = new Date();
    /* Data de expiração. Data atual + tempo de expiração */
    Date expiryDate = new Date(now.getTime() + jwtExpiration);

    /* Gera o token JWT */
    return Jwts.builder()
        .subject(id)
        .issuedAt(now)
        .expiration(expiryDate)
        .signWith(Keys.hmacShaKeyFor(jwtSecret.getBytes()))
        .compact();
  }

  /**
   * Extrai o token JWT do cabeçalho da requisição.
   * 
   * @param request a requisição HTTP contendo o cabeçalho de autorização
   * @return o token JWT extraído ou Optional.empty() se não encontrado
   */
  public Optional<String> extractToken(HttpServletRequest request) {
    String header = request.getHeader("Authorization");
    if (header != null && header.startsWith("Bearer ")) {
      return Optional.of(header.substring(7));
    }
    return Optional.empty();
  }

  /**
   * Valida se um token JWT é válido.
   * 
   * @param token o token JWT a ser validado
   * @return true se o token é válido, false caso contrário
   * @throws JwtAuthenticationException se o token for inválido
   */
  public boolean validateToken(String token) throws JwtAuthenticationException {
    try {
      Jwts.parser().verifyWith(Keys.hmacShaKeyFor(jwtSecret.getBytes())).build().parseSignedClaims(token);
      return true;
    } catch (ExpiredJwtException e) {
      throw new JwtAuthenticationException(
          JwtErrorMessages.JWT_TOKEN_EXPIRED.getMessage(),
          e.getMessage());

    } catch (MalformedJwtException e) {
      throw new JwtAuthenticationException(
          JwtErrorMessages.JWT_TOKEN_MALFORMED.getMessage(),
          e.getMessage());

    } catch (UnsupportedJwtException e) {
      throw new JwtAuthenticationException(
          JwtErrorMessages.JWT_TOKEN_UNSUPPORTED.getMessage(),
          e.getMessage());

    } catch (IllegalArgumentException e) {
      throw new JwtAuthenticationException(
          JwtErrorMessages.JWT_TOKEN_ILLEGAL_ARGUMENT.getMessage(),
          e.getMessage());

    } catch (Exception e) {
      throw new JwtAuthenticationException(
          JwtErrorMessages.JWT_AUTHENTICATION_ERROR.getMessage(),
          e.getMessage());
    }

  }

  /**
   * Obtém o ID do usuário a partir do token JWT.
   * 
   * @param token o token JWT a ser processado
   * @return o ID do usuário extraído do token
   * @throws JwtAuthenticationException se o token for inválido
   */
  public String getUserIdFromToken(String token) throws JwtAuthenticationException {
    try {
      return Jwts.parser().verifyWith(Keys.hmacShaKeyFor(jwtSecret.getBytes())).build()
          .parseSignedClaims(token).getPayload().getSubject();
    } catch (ExpiredJwtException e) {
      throw new JwtAuthenticationException(
          JwtErrorMessages.JWT_TOKEN_EXPIRED.getMessage(),
          e.getMessage());

    } catch (MalformedJwtException e) {
      throw new JwtAuthenticationException(
          JwtErrorMessages.JWT_TOKEN_MALFORMED.getMessage(),
          e.getMessage());

    } catch (UnsupportedJwtException e) {
      throw new JwtAuthenticationException(
          JwtErrorMessages.JWT_TOKEN_UNSUPPORTED.getMessage(),
          e.getMessage());

    } catch (IllegalArgumentException e) {
      throw new JwtAuthenticationException(
          JwtErrorMessages.JWT_TOKEN_ILLEGAL_ARGUMENT.getMessage(),
          e.getMessage());

    } catch (Exception e) {
      throw new JwtAuthenticationException(
          JwtErrorMessages.JWT_AUTHENTICATION_ERROR.getMessage(),
          e.getMessage());
    }
  }
}
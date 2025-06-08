package com.davi.desafio.backend.config;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Optional;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.davi.desafio.backend.constants.jwt.JwtErrorMessages;
import com.davi.desafio.backend.exceptions.JwtAuthenticationException;
import com.davi.desafio.backend.service.impl.JwtService;

/**
 * Filtro de autenticação JWT.
 */
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

  /* Serviço de geração e validação de tokens JWT */
  private final JwtService jwtService;

  /**
   * Construtor do filtro de autenticação JWT.
   * 
   * @param jwtService serviço de geração e validação de tokens JWT
   */
  public JwtAuthenticationFilter(JwtService jwtService) {
    this.jwtService = jwtService;
  }

  /**
   * Filtra as requisições HTTP para validar o token JWT.
   * 
   * @param request     a requisição HTTP
   * @param response    a resposta HTTP
   * @param filterChain o encadeamento de filtros
   */
  @Override
  protected void doFilterInternal(
      @NonNull HttpServletRequest request,
      @NonNull HttpServletResponse response,
      @NonNull FilterChain filterChain)
      throws ServletException, IOException, JwtAuthenticationException {

    if (isRoutePublic(request.getRequestURI())) {
      filterChain.doFilter(request, response);
      return;
    }

    try {
      /* Extrai o token JWT da requisição */
      Optional<String> token = jwtService.extractToken(request);
      /* Verifica se o token JWT foi encontrado dentro do cabeçalho da requisição */
      if (!token.isPresent()) {
        throw new JwtAuthenticationException(JwtErrorMessages.JWT_TOKEN_NOT_FOUND.getMessage(),
            JwtErrorMessages.JWT_AUTHENTICATION_ERROR.getMessage());
      }

      jwtService.validateToken(token.get());

      /* Obtém o ID do usuário a partir do token JWT */
      String userId = jwtService.getUserIdFromToken(token.get());

      /* Cria um objeto de autenticação */
      Authentication authentication = new UsernamePasswordAuthenticationToken(userId, null, new ArrayList<>());

      /* Define a autenticação no contexto de segurança */
      SecurityContextHolder.getContext().setAuthentication(authentication);

      /* Continua o encadeamento de filtros */
      filterChain.doFilter(request, response);

    } catch (JwtAuthenticationException e) {
      /* Retorna um erro 401 caso o token seja inválido */
      throw new JwtAuthenticationException(e.getJwtErrorMessages(), e.getErrorCode());
    }
  }

  /**
   * Verifica se a rota é pública.
   * 
   * @param path a rota a ser verificada
   * @return true se a rota é pública, false caso contrário
   */
  private Boolean isRoutePublic(String path) {
    return path.equals("/api/v1/health-check") ||
        path.startsWith("/api/v1/swagger-ui");
  }

}

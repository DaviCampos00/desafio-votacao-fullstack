package com.davi.desafio.backend.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

import lombok.Getter;
import lombok.Setter;

/**
 * Exceção lançada quando um token JWT é inválido.
 */
@Getter
@Setter
@ResponseStatus(HttpStatus.UNAUTHORIZED)
public class JwtAuthenticationException extends RuntimeException {

  /* Mensagem de erro */
  private final String jwtErrorMessages;

  /* Código de erro */
  private final String errorCode;

  /**
   * Construtor da exceção.
   * 
   * @param jwtErrorMessages a mensagem de erro
   */
  public JwtAuthenticationException(String jwtErrorMessages, String errorCode) {
    this.jwtErrorMessages = jwtErrorMessages;
    this.errorCode = errorCode;
  }

}

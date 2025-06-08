package com.davi.desafio.backend.exceptions;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ResponseStatus;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@ResponseStatus(HttpStatus.NOT_FOUND)
/**
 * Exceção lançada quando um recurso não é encontrado.
 */
public class NotFoundException extends RuntimeException {

  /* Mensagem de erro */
  private final String message;

  /**
   * Construtor da exceção.
   * 
   * @param message a mensagem de erro
   */
  public NotFoundException(String message) {
    this.message = message;
  }

}

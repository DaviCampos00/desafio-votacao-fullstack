package com.davi.desafio.backend.constants.jwt;

/**
 * Enumeração de mensagens de erro de JWT.
 */
public enum JwtErrorMessages {
  JWT_TOKEN_INVALID("Token JWT inválido"),
  JWT_TOKEN_EXPIRED("Token JWT expirado"),
  JWT_TOKEN_MALFORMED("Token JWT malformado"),
  JWT_TOKEN_UNSUPPORTED("Token JWT não suportado"),
  JWT_TOKEN_ILLEGAL_ARGUMENT("Token JWT argumento inválido"),
  JWT_AUTHENTICATION_ERROR("Erro de autenticação JWT"),
  JWT_TOKEN_NOT_FOUND("Token JWT não encontrado");

  /* Mensagem de erro */
  private final String message;

  /**
   * Construtor da enumeração.
   * 
   * @param message a mensagem de erro
   */
  JwtErrorMessages(String message) {
    this.message = message;
  }

  /**
   * Obtém a mensagem de erro.
   * 
   * @return a mensagem de erro
   */
  public String getMessage() {
    return message;
  }
}

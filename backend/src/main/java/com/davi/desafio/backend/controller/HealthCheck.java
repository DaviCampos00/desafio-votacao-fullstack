package com.davi.desafio.backend.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Classe responsável por verificar se a aplicação está funcionando.
 */
@RestController
public class HealthCheck {

  @GetMapping("/api/v1/health-check")
  public String health() {
    return "OK";
  }
}

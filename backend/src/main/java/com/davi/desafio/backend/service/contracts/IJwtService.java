package com.davi.desafio.backend.service.contracts;

import jakarta.servlet.http.HttpServletRequest;
import java.util.Optional;

public interface IJwtService {
  String generateToken(String id);

  Optional<String> extractToken(HttpServletRequest request);

  boolean validateToken(String token);

  String getUserIdFromToken(String token);
}

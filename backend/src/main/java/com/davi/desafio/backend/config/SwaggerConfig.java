package com.davi.desafio.backend.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import io.swagger.v3.oas.models.security.SecurityScheme;
import io.swagger.v3.oas.models.security.SecurityRequirement;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Configuração do Swagger/OpenAPI para documentação da API.
 */
@Configuration
public class SwaggerConfig {

  /**
   * Configura as informações da API para o Swagger.
   * 
   * @return configuração do OpenAPI
   */
  @Bean
  public OpenAPI customOpenAPI() {
    return new OpenAPI()
        .info(new Info()
            .title("API de Votação")
            .version("1.0.0")
            .license(new License()
                .name("MIT")
                .url("https://opensource.org/licenses/MIT")))
        .schemaRequirement("bearerAuth", new SecurityScheme()
            .type(SecurityScheme.Type.HTTP)
            .scheme("bearer")
            .bearerFormat("JWT"))
        .addSecurityItem(new SecurityRequirement().addList("bearerAuth"));
  }
}
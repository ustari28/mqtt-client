package com.alan.example.mosquito;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;


@Data
@Configuration
@ConfigurationProperties(prefix = "mqtt")
public class MqttConfig {
    private String username;
    private String password;
    private String url;
    private String clientId;
    private String[] topics;
    private String pathCa;
    private String[] permissions;
}

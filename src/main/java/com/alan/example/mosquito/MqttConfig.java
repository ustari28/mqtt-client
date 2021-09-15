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
    private String ca;
    private String crt;
    private String key;
    private String keyPassword;
}

package com.alan.example.mosquito;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Builder;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.eclipse.paho.client.mqttv3.IMqttClient;
import org.eclipse.paho.client.mqttv3.MqttException;
import org.eclipse.paho.client.mqttv3.MqttMessage;
import org.eclipse.paho.client.mqttv3.MqttPersistenceException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Random;
import java.util.concurrent.atomic.AtomicInteger;

@RestController
@Slf4j
public class ApiEndpoint {

    private final Random random = new Random();
    @Autowired
    private IMqttClient mqttClient;
    @Autowired
    private ObjectMapper mapper;
    @Autowired
    private MqttConfig config;
    private final AtomicInteger counter = new AtomicInteger();
    private final String[] types = {"type1", "type2", "type3"};

    @GetMapping("/message")
    public String message() {
        MqttMessage message = new MqttMessage();
        try {
            for (int i = 0; i < 20; i++) {
                Integer idMsg = counter.getAndIncrement();
                message.setPayload(mapper.writeValueAsBytes(MyMessage.builder().data("text")
                        .type(types[random.nextInt(types.length - 1)])
                        .id(idMsg)
                        .ts(System.currentTimeMillis()).build()));
                message.setId(idMsg);
                mqttClient.publish(config.getTopics()[0], message);
            }
            return "OK";
        } catch (JsonProcessingException e) {
            e.printStackTrace();
        } catch (MqttPersistenceException e) {
            e.printStackTrace();
        } catch (MqttException e) {
            e.printStackTrace();
        }

        return "KO";
    }


}

@Builder
@Data
class MyMessage {
    private Integer id;
    private String data;
    private String type;
    private Long ts;
}
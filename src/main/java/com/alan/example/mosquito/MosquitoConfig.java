package com.alan.example.mosquito;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.eclipse.paho.client.mqttv3.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Base64;
import java.util.logging.Logger;

@Configuration
@Slf4j
public class MosquitoConfig {
    @Autowired
    private MqttConfig mqttConfig;

    public static String generateSasToken(String resourceUri, String key) throws Exception {
        // Token will expire in one hour
        long expiry = Instant.now().getEpochSecond() + 3600;

        String stringToSign = URLEncoder.encode(resourceUri, StandardCharsets.UTF_8) + "\n" + expiry;
        byte[] decodedKey = Base64.getDecoder().decode(key);

        Mac sha256HMAC = Mac.getInstance("HmacSHA256");
        SecretKeySpec secretKey = new SecretKeySpec(decodedKey, "HmacSHA256");
        sha256HMAC.init(secretKey);
        Base64.Encoder encoder = Base64.getEncoder();

        String signature = new String(encoder.encode(
                sha256HMAC.doFinal(stringToSign.getBytes(StandardCharsets.UTF_8))), StandardCharsets.UTF_8);

        String token = "SharedAccessSignature sr=" + URLEncoder.encode(resourceUri, StandardCharsets.UTF_8)
                + "&sig=" + URLEncoder.encode(signature, StandardCharsets.UTF_8.name()) + "&se=" + expiry; //DIRECT HUB
                //+ "&sig=" + URLEncoder.encode(signature, StandardCharsets.UTF_8.name()) + "&skn=registration"; //DPS

        return token;
    }

    public static SSLSocketFactory getSocketFactory(final String caCrtFile)
            throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // load CA certificate
        X509Certificate caCert = null;

        InputStream bis = new ByteArrayInputStream(caCrtFile.getBytes(StandardCharsets.UTF_8));
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        while (bis.available() > 0) {
            caCert = (X509Certificate) cf.generateCertificate(bis);
            // System.out.println(caCert.toString());
        }

        // CA certificate is used to authenticate server
        KeyStore caKs = KeyStore.getInstance(KeyStore.getDefaultType());
        caKs.load(null, null);
        caKs.setCertificateEntry("ca-certificate", caCert);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance("X509");
        tmf.init(caKs);

        // client key and certificates are sent to server so it can authenticate
        // us
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory
                .getDefaultAlgorithm());
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);
        kmf.init(ks, null);

        // finally, create SSL socket factory
        SSLContext context = SSLContext.getInstance("TLSv1.2");
        context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        return context.getSocketFactory();
    }

    @Bean
    public IMqttClient mqttClient() {
        MqttConnectOptions connectOptions = new MqttConnectOptions();
        connectOptions.setUserName(mqttConfig.getUsername());
        try {
            connectOptions.setPassword(generateSasToken(mqttConfig.getPermissions()[0],
                    mqttConfig.getPassword()).toCharArray());
            SSLSocketFactory socketFactory = MosquitoConfig.getSocketFactory(mqttConfig.getPathCa());
            connectOptions.setSocketFactory(socketFactory);
            IMqttClient client = new MqttClient(mqttConfig.getUrl(), mqttConfig.getClientId());
            log.info("connecting to {} {} {}", mqttConfig.getClientId(), mqttConfig.getTopics()[0],
                    mqttConfig.getPermissions()[0]);
            client.connect(connectOptions);
            log.info("Connected to iot hub");
            client.subscribe(mqttConfig.getTopics()[0], 0);
            log.info("Subscribed to iot hub");
            return client;
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

    }
}

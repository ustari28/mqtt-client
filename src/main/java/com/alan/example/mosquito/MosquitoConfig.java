package com.alan.example.mosquito;

import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.eclipse.paho.client.mqttv3.MqttConnectOptions;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.integration.annotation.ServiceActivator;
import org.springframework.integration.channel.DirectChannel;
import org.springframework.integration.core.MessageProducer;
import org.springframework.integration.mqtt.core.DefaultMqttPahoClientFactory;
import org.springframework.integration.mqtt.inbound.MqttPahoMessageDrivenChannelAdapter;
import org.springframework.integration.mqtt.support.DefaultPahoMessageConverter;
import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.MessageHandler;
import org.springframework.messaging.MessagingException;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

@Configuration
@Slf4j
public class MosquitoConfig {
    @Autowired
    private MqttConfig mqttConfig;

    public static SSLSocketFactory getSocketFactory(final String caCrtFile,
                                                    final String crtFile,
                                                    final String keyFile,
                                                    final String password,
                                                    final String tlsVersion)
            throws Exception {
        log.info("TLS version {}", tlsVersion);
        Security.addProvider(new BouncyCastleProvider());
        // CA certificate is used to authenticate server
        KeyStore caKs = KeyStore.getInstance(KeyStore.getDefaultType());
        caKs.load(null, null);
        // load CA certificate
        X509Certificate caCert = null;

        InputStream bis = new ByteArrayInputStream(caCrtFile.getBytes(StandardCharsets.UTF_8));
        CertificateFactory cf = CertificateFactory.getInstance("X.509");

        int index = 0;
        while (bis.available() > 0) {
            caCert = (X509Certificate) cf.generateCertificate(bis);
            X500Name x500Name = new X500Name(caCert.getSubjectX500Principal().getName());
            caKs.setCertificateEntry(x500Name.getRDNs(BCStyle.CN)[0].getFirst().getValue().toASN1Primitive().toString(), caCert);
            log.info("Cargando {}", x500Name.getRDNs(BCStyle.CN)[0].getFirst().getValue().toASN1Primitive().toString());
        }

        // load client certificate
        bis = new ByteArrayInputStream(crtFile.getBytes(StandardCharsets.UTF_8));
        X509Certificate cert = null;
        while (bis.available() > 0) {
            cert = (X509Certificate) cf.generateCertificate(bis);
        }

        // load client private key
        PEMParser pemParser = new PEMParser(new StringReader(keyFile));
        Object object = pemParser.readObject();

        PrivateKey prvKey = null;
        if (object instanceof PEMEncryptedKeyPair) {
            log.info("PEMEncryptedKeyPair key - we will use provided password");
            PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder()
                    .build(password.toCharArray());
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter()
                    .setProvider("BC");
            prvKey = converter.getKeyPair(((PEMEncryptedKeyPair) object)
                    .decryptKeyPair(decProv)).getPrivate();
        } else if (object instanceof PEMKeyPair) {
            log.info("PEMKeyPair key - no password needed");
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter()
                    .setProvider("BC");
            prvKey = converter.getKeyPair((PEMKeyPair) object).getPrivate();
        } else if (object instanceof PrivateKeyInfo) {
            log.info("PrivateKeyInfo key - no password needed");
            JcaPEMKeyConverter converter = new JcaPEMKeyConverter();
            prvKey = converter.getPrivateKey((PrivateKeyInfo) object);
        } else {
            throw new UnsupportedOperationException("Private kay format doesn't supported");
        }
        pemParser.close();

        TrustManagerFactory tmf = TrustManagerFactory.getInstance("X509");
        tmf.init(caKs);


        // client key and certificates are sent to server so it can authenticate
        // us
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        ks.load(null, null);
        ks.setCertificateEntry("certificate", cert);
        ks.setKeyEntry("private-key", prvKey, password.toCharArray(),
                new java.security.cert.Certificate[]{cert});
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory
                .getDefaultAlgorithm());
        kmf.init(ks, password.toCharArray());

        // finally, create SSL socket factory
        SSLContext context = SSLContext.getInstance(tlsVersion);
        context.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        return context.getSocketFactory();
    }

    @Bean
    public MessageChannel mqttInputChannel() {
        return new DirectChannel();
    }

    @Bean
    public DefaultMqttPahoClientFactory defaultClientFactory() {
        MqttConnectOptions connectOptions = new MqttConnectOptions();
        connectOptions.setUserName(mqttConfig.getUsername());
        connectOptions.setPassword(mqttConfig.getPassword().toCharArray());
        DefaultMqttPahoClientFactory factory = new DefaultMqttPahoClientFactory();
        try {

            connectOptions.setSocketFactory(getSocketFactory(mqttConfig.getCa(),
                    mqttConfig.getCrt(), mqttConfig.getKey(), mqttConfig.getKeyPassword(), "TLSv1.3"));
            connectOptions.setHttpsHostnameVerificationEnabled(false);
            factory.setConnectionOptions(connectOptions);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return factory;
    }

    @Bean
    public MessageProducer inbound() {
        MqttPahoMessageDrivenChannelAdapter adapter =
                new MqttPahoMessageDrivenChannelAdapter(mqttConfig.getUrl(), mqttConfig.getClientId(), defaultClientFactory(),
                        mqttConfig.getTopics());
        adapter.setCompletionTimeout(5000);
        adapter.setConverter(new DefaultPahoMessageConverter());
        adapter.setQos(1);
        adapter.setOutputChannel(mqttInputChannel());
        return adapter;
    }

    @Bean
    @ServiceActivator(inputChannel = "mqttInputChannel")
    public MessageHandler messageHandler() {
        return new MessageHandler() {

            @Override
            public void handleMessage(Message<?> message) throws MessagingException {
                System.out.println(message.getPayload());
            }

        };
    }
}

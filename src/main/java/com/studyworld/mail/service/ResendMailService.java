package com.studyworld.mail.service;

import com.studyworld.config.MailProperties;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

@Service
public class ResendMailService implements MailService {

    private static final Logger log = LoggerFactory.getLogger(ResendMailService.class);

    private static final String RESEND_ENDPOINT = "https://api.resend.com/emails";

    private final RestTemplate restTemplate;
    private final MailProperties mailProperties;

    public ResendMailService(MailProperties mailProperties, RestTemplateBuilder builder) {
        this.mailProperties = mailProperties;
        this.restTemplate = builder
                .setConnectTimeout(Duration.ofSeconds(10))
                .setReadTimeout(Duration.ofSeconds(15))
                .build();
        validateConfiguration();
    }

    private void validateConfiguration() {
        String fromEmail = mailProperties.fromEmail();
        String apiKey = mailProperties.resend() != null ? mailProperties.resend().apiKey() : null;
        if (fromEmail == null || fromEmail.isBlank()) {
            throw new IllegalStateException("app.mail.from-email must be set (Resend verified sender/domain)");
        }
        if (apiKey == null || apiKey.isBlank()) {
            throw new IllegalStateException("app.mail.resend.api-key must be set");
        }
    }

    @Override
    public void sendHtmlMail(String to, String subject, String htmlBody) {
        String apiKey = mailProperties.resend().apiKey();
        String fromEmail = mailProperties.fromEmail();
        String fromName = mailProperties.fromName();
        String from = (fromName != null && !fromName.isBlank()) ? String.format("%s <%s>", fromName, fromEmail) : fromEmail;

        Map<String, Object> payload = new HashMap<>();
        payload.put("from", from);
        payload.put("to", to);
        payload.put("subject", subject);
        payload.put("html", htmlBody);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set("Authorization", "Bearer " + apiKey);

        try {
            HttpEntity<Map<String, Object>> entity = new HttpEntity<>(payload, headers);
            restTemplate.postForEntity(RESEND_ENDPOINT, entity, String.class);
        } catch (RestClientException ex) {
            log.error("Failed to send email via Resend: {}", ex.getMessage());
        }
    }
}


package com.studyworld.mail.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

@Service
public class DefaultMailService implements MailService {

    private static final Logger log = LoggerFactory.getLogger(DefaultMailService.class);
    // Intentionally not sending real emails in this environment.
    // Keeping constructor minimal to avoid requiring SMTP configuration.
    public DefaultMailService() {}

    @Override
    public void sendHtmlMail(String to, String subject, String htmlBody) {
        // Mock mail delivery: log to console for testing flows on Railway/local
        log.info("[MAIL MOCK] To: {} | Subject: {}\n{}", to, subject, htmlBody);
    }
}

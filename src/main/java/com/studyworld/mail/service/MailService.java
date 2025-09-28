package com.studyworld.mail.service;

public interface MailService {

    void sendHtmlMail(String to, String subject, String htmlBody);
}

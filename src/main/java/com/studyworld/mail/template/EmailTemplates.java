package com.studyworld.mail.template;

import java.nio.charset.StandardCharsets;
import java.util.Locale;
import org.springframework.context.MessageSource;
import org.springframework.stereotype.Component;

@Component
public class EmailTemplates {

    private final MessageSource messages;

    public EmailTemplates(MessageSource messages) {
        this.messages = messages;
    }

    public String verificationEmail(String verifyUrl, String ttlText, Locale locale) {
        String brand = m("email.brand", locale);
        String heading = m("email.verify.heading", locale);
        String intro = "<p>" + m("email.verify.intro1", locale) + "</p>" +
                "<p>" + m("email.verify.intro2", locale) + "</p>";
        String ctaText = m("email.verify.cta", locale);
        String outro = "<p style=\"color:#6b7280;margin:24px 0 0\">" +
                ms("email.verify.outro", locale, ttlText) + "</p>";
        return actionEmail(brand, heading, intro, ctaText, verifyUrl, outro, locale);
    }

    public String passwordResetEmail(String resetUrl, String ttlText, Locale locale) {
        String brand = m("email.brand", locale);
        String heading = m("email.reset.heading", locale);
        String intro = "<p>" + m("email.reset.intro1", locale) + "</p>" +
                "<p>" + m("email.reset.intro2", locale) + "</p>";
        String ctaText = m("email.reset.cta", locale);
        String outro = "<p style=\"color:#6b7280;margin:24px 0 0\">" +
                ms("email.reset.outro", locale, ttlText) + "</p>";
        return actionEmail(brand, heading, intro, ctaText, resetUrl, outro, locale);
    }

    private String actionEmail(String brand, String heading, String introHtml, String ctaText, String ctaUrl, String footerHtml, Locale locale) {
        // Simple, inline-styled email compatible with most clients
        StringBuilder sb = new StringBuilder(2048);
        sb.append("<!doctype html><html><head><meta charset=\"")
          .append(StandardCharsets.UTF_8.name())
          .append("\"><meta name=\"viewport\" content=\"width=device-width\">\n")
          .append("<title>")
          .append(escape(brand)).append("</title></head><body style=\"margin:0;padding:0;background:#f6f8fb;\">\n");

        // Header
        sb.append("<div style=\"background:#0c0c0c;color:#fff;padding:16px 24px;text-align:center;\">")
          .append("<div style=\"font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif;font-weight:800;letter-spacing:1px;text-transform:uppercase;\">")
          .append(escape(brand))
          .append("</div></div>\n");

        // Card
        sb.append("<div style=\"max-width:560px;margin:24px auto;padding:0 16px;\">\n")
          .append("<div style=\"background:#ffffff;border:1px solid #e5e7eb;border-radius:12px;padding:24px;box-shadow:0 1px 2px rgba(0,0,0,0.04);\">\n")
          .append("<h1 style=\"margin:0 0 12px;font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif;font-size:20px;color:#0c0c0c;\">")
          .append(escape(heading))
          .append("</h1>\n")
          .append("<div style=\"font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif;font-size:14px;line-height:1.5;color:#0f172a;\">")
          .append(introHtml)
          .append("</div>\n")
          .append("<div style=\"margin-top:20px;\"><a href=\"")
          .append(escapeAttr(ctaUrl))
          .append("\" style=\"display:inline-block;background:#000;color:#fff;text-decoration:none;padding:12px 18px;border-radius:999px;font-weight:700;font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif;\">")
          .append(escape(ctaText))
          .append("</a></div>\n")
          .append("<div style=\"font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif;font-size:12px;line-height:1.4;color:#64748b;\">")
          .append(footerHtml)
          .append("</div>\n")
          .append("</div>\n</div>\n");

        // Footer
        sb.append("<div style=\"text-align:center;color:#94a3b8;font-size:12px;font-family:Inter,system-ui,-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif;margin:16px 0 24px;\">")
          .append("© ")
          .append(escape(brand))
          .append(". ")
          .append(escape(m("email.footer", locale)))
          .append("</div>");

        sb.append("</body></html>");
        return sb.toString();
    }

    private String m(String key, Locale locale) {
        return messages.getMessage(key, null, locale);
    }

    private String ms(String key, Locale locale, Object... args) {
        return messages.getMessage(key, args, locale);
    }

    private static String escape(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;");
    }

    private static String escapeAttr(String s) {
        // For attributes, also replace single quotes
        return escape(s).replace("'", "&#39;");
    }
}

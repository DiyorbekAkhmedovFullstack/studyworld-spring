package com.studyworld.mail.template;

import java.nio.charset.StandardCharsets;

public final class EmailTemplates {

    private EmailTemplates() {}

    public static String verificationEmail(String verifyUrl, String ttlText) {
        String intro = "<p>Welcome to <strong>StudiWelt</strong> — we’re excited to have you.</p>"
                + "<p>To activate your account, confirm your email address.</p>";
        String outro = "<p style=\"color:#6b7280;margin:24px 0 0\">This link expires in " + escape(ttlText) + ".</p>";
        return actionEmail(
                "Verify your email",
                intro,
                "Verify email",
                verifyUrl,
                outro
        );
    }

    public static String passwordResetEmail(String resetUrl, String ttlText) {
        String intro = "<p>We received a request to reset your password.</p>"
                + "<p>Click the button below to choose a new password.</p>";
        String outro = "<p style=\"color:#6b7280;margin:24px 0 0\">This link expires in " + escape(ttlText) + ". If you didn’t request a reset, you can safely ignore this message.</p>";
        return actionEmail(
                "Reset your password",
                intro,
                "Reset password",
                resetUrl,
                outro
        );
    }

    private static String actionEmail(String heading, String introHtml, String ctaText, String ctaUrl, String footerHtml) {
        String brand = "StudiWelt";
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
          .append(". All rights reserved.")
          .append("</div>");

        sb.append("</body></html>");
        return sb.toString();
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


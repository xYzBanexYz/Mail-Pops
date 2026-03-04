package serverPKG;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import it.unisa.dia.gas.jpbc.Element;
import it.unisa.dia.gas.jpbc.Pairing;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import javax.mail.*;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;

import java.io.IOException;
import java.io.OutputStream;
import java.io.UncheckedIOException;
import java.net.InetSocketAddress;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ServerPKG {

    // ===== JPBC =====
    private static Pairing pairing;
    private static Element P;
    private static Element s;
    private static Element Ppub;

    // ===== Files (JSON) =====
    private static final Path DATA_DIR = Paths.get("data");
    private static final Path PARAMS_FILE = DATA_DIR.resolve("params.json");
    private static final Path OTP_FILE = DATA_DIR.resolve("otp.json");
    private static final Path IP_FILE = DATA_DIR.resolve("ip.json");

    private static final Object FILE_LOCK = new Object();

    // ===== OTP store =====
    private static final class OtpEntry {
        final String code;          // 6 digits
        final long expiresAtEpoch;  // epoch seconds
        final long createdAtEpoch;  // epoch seconds
        int attempts;

        OtpEntry(String code, long createdAtEpoch, long expiresAtEpoch, int attempts) {
            this.code = code;
            this.createdAtEpoch = createdAtEpoch;
            this.expiresAtEpoch = expiresAtEpoch;
            this.attempts = attempts;
        }

        boolean isExpired(long nowEpoch) {
            return nowEpoch > expiresAtEpoch;
        }
    }

    private static final ConcurrentHashMap<String, OtpEntry> OTP_BY_EMAIL = new ConcurrentHashMap<>();
    private static final SecureRandom RNG = new SecureRandom();

    // 15 minutes
    private static final long OTP_TTL_SECONDS = 15 * 60;
    // limite bruteforce simple
    private static final int MAX_ATTEMPTS = 8;

    // Anti-spam (une demande toutes les 30 sec pour le même email)
    private static final long EMAIL_REQUEST_COOLDOWN_SECONDS = 30;

    // Limite basique par IP (60 requêtes / 5 min)
    private static final int IP_WINDOW_MAX = 60;
    private static final long IP_WINDOW_SECONDS = 5 * 60;

    private static final class IpWindow {
        long windowStartEpoch;
        int count;
        IpWindow(long windowStartEpoch, int count) {
            this.windowStartEpoch = windowStartEpoch;
            this.count = count;
        }
    }

    private static final ConcurrentHashMap<String, IpWindow> IP_LIMIT = new ConcurrentHashMap<>();

    // Validation email (simple mais correcte pour usage pratique)
    private static final Pattern EMAIL_RE =
            Pattern.compile("^[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}$", Pattern.CASE_INSENSITIVE);

    // ===== Gmail SMTP config via ENV (recommandé) =====
    private static String GMAIL_FROM;
    private static String GMAIL_APP_PASSWORD;

    private static final String SMTP_HOST = "smtp.gmail.com";
    private static final int SMTP_PORT = 587;

    // ===== Safety wrapper to avoid "Empty reply from server" =====
    @FunctionalInterface
    private interface ExchangeHandler {
        void handle(HttpExchange exchange) throws Exception;
    }

    private static void safeHandle(HttpExchange exchange, ExchangeHandler handler) throws IOException {
        try {
            handler.handle(exchange);
        } catch (Throwable t) {
            t.printStackTrace();
            sendJson(exchange, 500, "{\"error\":\"internal_server_error\"}");
        }
    }

    public static void main(String[] args) throws Exception {

        // Secrets depuis env
        GMAIL_FROM = envOrNull("PKG_GMAIL_FROM");
        GMAIL_APP_PASSWORD = envOrNull("PKG_GMAIL_APP_PASSWORD");

        // TEMP (à éviter) : si tu veux forcer en dur, dé-commente ces 2 lignes
        GMAIL_FROM = "projetcrypto85@gmail.com";
        GMAIL_APP_PASSWORD = "dbjgpkubgfupuspc";

        if (GMAIL_FROM == null || GMAIL_APP_PASSWORD == null) {
            throw new IllegalStateException(
                    "Missing env vars. Please set PKG_GMAIL_FROM and PKG_GMAIL_APP_PASSWORD.");
        }
        GMAIL_APP_PASSWORD = GMAIL_APP_PASSWORD.replaceAll("\\s+", "");

        System.out.println("=== Initialisation du PKG ===");

        pairing = PairingFactory.getPairing("params/curves/a.properties");

        // Prépare le répertoire data/
        Files.createDirectories(DATA_DIR);

        // Charge/initialise les paramètres persistés (P, s, Ppub)
        loadOrInitParams();

        // Charge OTP et IP windows depuis JSON
        loadOtpStore();
        loadIpStore();

        System.out.println("PKG prêt. (paramètres persistés dans " + PARAMS_FILE.toAbsolutePath() + ")");

        int port = envIntOrDefault("PKG_BIND_PORT", 8080);

        HttpServer server = HttpServer.create(new InetSocketAddress(port), 0);

        server.createContext("/params", ex -> safeHandle(ex, ServerPKG::handleParams));
        server.createContext("/auth/request", ex -> safeHandle(ex, ServerPKG::handleAuthRequest));
        server.createContext("/auth/confirm", ex -> safeHandle(ex, ServerPKG::handleAuthConfirm));

        server.setExecutor(null);
        server.start();

        System.out.println("Serveur PKG lancé sur http://localhost:" + port);
        System.out.println("GET  /params");
        System.out.println("POST /auth/request  (email=...)");
        System.out.println("POST /auth/confirm  (email=...&code=......)");
    }

    // ========================
    // GET /params
    // ========================
    private static void handleParams(HttpExchange exchange) throws IOException {
        if (!exchange.getRequestMethod().equalsIgnoreCase("GET")) {
            sendJson(exchange, 405, "{\"error\":\"method_not_allowed\"}");
            return;
        }

        if (!rateLimitIp(exchange)) return;

        String response = "{\n" +
                "\"P\":\"" + Base64.getEncoder().encodeToString(P.toBytes()) + "\",\n" +
                "\"Ppub\":\"" + Base64.getEncoder().encodeToString(Ppub.toBytes()) + "\"\n" +
                "}";

        sendJson(exchange, 200, response);
    }

    // ========================
    // POST /auth/request
    // body: email=...
    // ========================
    private static void handleAuthRequest(HttpExchange exchange) throws IOException {
        if (!exchange.getRequestMethod().equalsIgnoreCase("POST")) {
            sendJson(exchange, 405, "{\"error\":\"method_not_allowed\"}");
            return;
        }

        if (!rateLimitIp(exchange)) return;

        cleanupExpiredOtps(); // supprime expirés + flush JSON

        Map<String, String> form = readFormUrlEncoded(exchange);
        String email = form.get("email");

        if (email == null || !isValidEmail(email)) {
            sendJson(exchange, 400, "{\"error\":\"invalid_email\"}");
            return;
        }

        String emailKey = email.toLowerCase(Locale.ROOT);
        long now = Instant.now().getEpochSecond();

        // Cooldown anti-spam pour le même email
        OtpEntry existing = OTP_BY_EMAIL.get(emailKey);
        if (existing != null && (now - existing.createdAtEpoch) < EMAIL_REQUEST_COOLDOWN_SECONDS) {
            long wait = EMAIL_REQUEST_COOLDOWN_SECONDS - (now - existing.createdAtEpoch);
            sendJson(exchange, 429, "{\"error\":\"cooldown\",\"retry_after_seconds\":" + wait + "}");
            return;
        }

        // Génère OTP 6 chiffres
        String code = String.format("%06d", RNG.nextInt(1_000_000));
        long expiresAt = now + OTP_TTL_SECONDS;

        OTP_BY_EMAIL.put(emailKey, new OtpEntry(code, now, expiresAt, 0));
        persistOtpStore(); // <- persist JSON

        try {
            // Debug utile pour tester (désactive en prod)
            System.out.println("DEBUG OTP for " + email + " = " + code);
            sendOtpEmail(email, code);
        } catch (Exception e) {
            e.printStackTrace();
            sendJson(exchange, 500, "{\"error\":\"email_send_failed\"}");
            return;
        }

        sendJson(exchange, 200, "{\"status\":\"code_sent\",\"ttl_seconds\":" + OTP_TTL_SECONDS + "}");
    }

    // ========================
    // POST /auth/confirm
    // body: email=...&code=123456
    // ========================
    private static void handleAuthConfirm(HttpExchange exchange) throws IOException {
        if (!exchange.getRequestMethod().equalsIgnoreCase("POST")) {
            sendJson(exchange, 405, "{\"error\":\"method_not_allowed\"}");
            return;
        }

        if (!rateLimitIp(exchange)) return;

        cleanupExpiredOtps(); // supprime expirés + flush JSON

        Map<String, String> form = readFormUrlEncoded(exchange);
        String email = form.get("email");
        String code = form.get("code");

        if (email == null || code == null || !isValidEmail(email) || !code.matches("^\\d{6}$")) {
            sendJson(exchange, 400, "{\"error\":\"bad_request\"}");
            return;
        }

        String key = email.toLowerCase(Locale.ROOT);
        OtpEntry entry = OTP_BY_EMAIL.get(key);

        if (entry == null) {
            sendJson(exchange, 401, "{\"error\":\"no_challenge\"}");
            return;
        }

        long now = Instant.now().getEpochSecond();

        if (entry.isExpired(now)) {
            OTP_BY_EMAIL.remove(key);
            persistOtpStore();
            sendJson(exchange, 401, "{\"error\":\"code_expired\"}");
            return;
        }

        if (entry.attempts >= MAX_ATTEMPTS) {
            OTP_BY_EMAIL.remove(key);
            persistOtpStore();
            sendJson(exchange, 429, "{\"error\":\"too_many_attempts\"}");
            return;
        }

        entry.attempts++;
        persistOtpStore(); // persiste les tentatives

        if (!entry.code.equals(code)) {
            sendJson(exchange, 401,
                    "{\"error\":\"invalid_code\",\"attempts_left\":" + (MAX_ATTEMPTS - entry.attempts) + "}");
            return;
        }

        // Succès: on invalide le code (1-time)
        OTP_BY_EMAIL.remove(key);
        persistOtpStore();

        // Génération clé privée = s * H(email)
        byte[] emailBytes = email.getBytes(StandardCharsets.UTF_8);
        Element Q = pairing.getG1().newElement()
                .setFromHash(emailBytes, 0, emailBytes.length)
                .getImmutable();

        Element d = Q.duplicate().powZn(s).getImmutable();

        String response = "{\n" +
                "\"id\":\"" + escapeJson(email) + "\",\n" +
                "\"privateKey\":\"" + Base64.getEncoder().encodeToString(d.toBytes()) + "\"\n" +
                "}";

        sendJson(exchange, 200, response);
    }

    // ===== Email utils (Gmail SMTP) =====
    private static void sendOtpEmail(String toEmail, String code) throws Exception {
        Properties props = new Properties();
        props.put("mail.smtp.auth", "true");
        props.put("mail.smtp.starttls.enable", "true");
        props.put("mail.smtp.starttls.required", "true");
        props.put("mail.smtp.host", SMTP_HOST);
        props.put("mail.smtp.port", String.valueOf(SMTP_PORT));

        props.put("mail.smtp.connectiontimeout", "10000");
        props.put("mail.smtp.timeout", "10000");
        props.put("mail.smtp.writetimeout", "10000");

        Session session = Session.getInstance(props, new Authenticator() {
            @Override protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(GMAIL_FROM, GMAIL_APP_PASSWORD);
            }
        });

        Message message = new MimeMessage(session);
        message.setFrom(new InternetAddress(GMAIL_FROM));
        message.setRecipients(Message.RecipientType.TO, InternetAddress.parse(toEmail));
        message.setSubject("Votre code PKG (valable 15 minutes)");

        String body = ""
                + "Bonjour,\n\n"
                + "Votre code de confirmation PKG est : " + code + "\n"
                + "Il est valable 15 minutes.\n\n"
                + "Si vous n'êtes pas à l'origine de cette demande, ignorez ce message.\n";

        message.setText(body);
        Transport.send(message);
    }

    // ===== Cleanup OTP =====
    private static void cleanupExpiredOtps() {
        long now = Instant.now().getEpochSecond();
        boolean changed = false;

        for (Map.Entry<String, OtpEntry> e : OTP_BY_EMAIL.entrySet()) {
            if (e.getValue().isExpired(now)) {
                OTP_BY_EMAIL.remove(e.getKey());
                changed = true;
            }
        }

        if (changed) persistOtpStore();
    }

    // ===== Rate limit IP (persisté JSON) =====
    private static boolean rateLimitIp(HttpExchange exchange) throws IOException {
        String ip = exchange.getRemoteAddress().getAddress().getHostAddress();
        long now = Instant.now().getEpochSecond();

        IpWindow w = IP_LIMIT.get(ip);
        if (w == null) {
            IP_LIMIT.put(ip, new IpWindow(now, 1));
            persistIpStore();
            return true;
        }

        if ((now - w.windowStartEpoch) > IP_WINDOW_SECONDS) {
            w.windowStartEpoch = now;
            w.count = 1;
            persistIpStore();
            return true;
        }

        w.count++;
        persistIpStore();

        if (w.count > IP_WINDOW_MAX) {
            sendJson(exchange, 429, "{\"error\":\"rate_limited\"}");
            return false;
        }
        return true;
    }

    // ===== HTTP helpers =====
    private static Map<String, String> readFormUrlEncoded(HttpExchange exchange) throws IOException {
        byte[] raw = exchange.getRequestBody().readAllBytes();
        String body = new String(raw, StandardCharsets.UTF_8);

        Map<String, String> result = new HashMap<>();
        if (body.isBlank()) return result;

        for (String pair : body.split("&")) {
            String[] kv = pair.split("=", 2);
            String k = urlDecode(kv[0]);
            String v = kv.length > 1 ? urlDecode(kv[1]) : "";
            result.put(k, v);
        }
        return result;
    }

    private static void sendJson(HttpExchange exchange, int status, String json) throws IOException {
        byte[] bytes = json.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream os = exchange.getResponseBody()) {
            os.write(bytes);
        }
    }

    private static String urlDecode(String s) throws IOException {
        return URLDecoder.decode(s, StandardCharsets.UTF_8);
    }

    private static boolean isValidEmail(String email) {
        return EMAIL_RE.matcher(email).matches();
    }

    private static String escapeJson(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    private static String envOrNull(String key) {
        String v = System.getenv(key);
        if (v == null) return null;
        v = v.trim();
        return v.isEmpty() ? null : v;
    }

    private static int envIntOrDefault(String key, int def) {
        String v = envOrNull(key);
        if (v == null) return def;
        try { return Integer.parseInt(v); }
        catch (NumberFormatException e) { return def; }
    }

    // =========================
    // JSON persistence (no external lib)
    // =========================

    private static void loadOrInitParams() {
        synchronized (FILE_LOCK) {
            if (Files.exists(PARAMS_FILE)) {
                try {
                    String json = Files.readString(PARAMS_FILE, StandardCharsets.UTF_8);

                    String pB64 = JsonMini.getString(json, "P");
                    String sB64 = JsonMini.getString(json, "s");
                    String ppubB64 = JsonMini.getString(json, "Ppub");

                    if (pB64 == null || sB64 == null || ppubB64 == null) {
                        throw new IllegalStateException("params.json missing fields");
                    }

                    P = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(pB64)).getImmutable();
                    s = pairing.getZr().newElementFromBytes(Base64.getDecoder().decode(sB64)).getImmutable();
                    Ppub = pairing.getG1().newElementFromBytes(Base64.getDecoder().decode(ppubB64)).getImmutable();

                    return;
                } catch (Exception e) {
                    System.err.println("Impossible de charger params.json, régénération. Cause: " + e.getMessage());
                }
            }

            // Init fresh and persist
            P = pairing.getG1().newRandomElement().getImmutable();
            s = pairing.getZr().newRandomElement().getImmutable();
            Ppub = P.duplicate().powZn(s).getImmutable();
            persistParams();
        }
    }

    private static void persistParams() {
        synchronized (FILE_LOCK) {
            String json = "{\n" +
                    "  \"P\":\"" + Base64.getEncoder().encodeToString(P.toBytes()) + "\",\n" +
                    "  \"s\":\"" + Base64.getEncoder().encodeToString(s.toBytes()) + "\",\n" +
                    "  \"Ppub\":\"" + Base64.getEncoder().encodeToString(Ppub.toBytes()) + "\"\n" +
                    "}\n";
            writeAtomic(PARAMS_FILE, json);
        }
    }

    private static void loadOtpStore() {
        synchronized (FILE_LOCK) {
            if (!Files.exists(OTP_FILE)) return;

            try {
                String json = Files.readString(OTP_FILE, StandardCharsets.UTF_8);
                Map<String, Map<String, String>> entries = JsonMini.parseTopObjectOfObjects(json);

                for (Map.Entry<String, Map<String, String>> e : entries.entrySet()) {
                    String email = e.getKey();
                    Map<String, String> obj = e.getValue();

                    String code = obj.get("code");
                    long createdAt = parseLong(obj.get("createdAt"), 0);
                    long expiresAt = parseLong(obj.get("expiresAt"), 0);
                    int attempts = (int) parseLong(obj.get("attempts"), 0);

                    if (code != null && code.matches("^\\d{6}$") && createdAt > 0 && expiresAt > 0) {
                        OTP_BY_EMAIL.put(email, new OtpEntry(code, createdAt, expiresAt, attempts));
                    }
                }
            } catch (Exception e) {
                System.err.println("Impossible de charger otp.json (ignoré). Cause: " + e.getMessage());
            }
        }
    }

    private static void persistOtpStore() {
        synchronized (FILE_LOCK) {
            StringBuilder sb = new StringBuilder();
            sb.append("{\n");
            int i = 0;
            for (Map.Entry<String, OtpEntry> e : OTP_BY_EMAIL.entrySet()) {
                String email = e.getKey();
                OtpEntry o = e.getValue();

                if (i++ > 0) sb.append(",\n");
                sb.append("  \"").append(JsonMini.escape(email)).append("\": ");
                sb.append("{");
                sb.append("\"code\":\"").append(o.code).append("\",");
                sb.append("\"createdAt\":").append(o.createdAtEpoch).append(",");
                sb.append("\"expiresAt\":").append(o.expiresAtEpoch).append(",");
                sb.append("\"attempts\":").append(o.attempts);
                sb.append("}");
            }
            sb.append("\n}\n");
            writeAtomic(OTP_FILE, sb.toString());
        }
    }

    private static void loadIpStore() {
        synchronized (FILE_LOCK) {
            if (!Files.exists(IP_FILE)) return;

            try {
                String json = Files.readString(IP_FILE, StandardCharsets.UTF_8);
                Map<String, Map<String, String>> entries = JsonMini.parseTopObjectOfObjects(json);

                for (Map.Entry<String, Map<String, String>> e : entries.entrySet()) {
                    String ip = e.getKey();
                    Map<String, String> obj = e.getValue();

                    long windowStart = parseLong(obj.get("windowStart"), 0);
                    int count = (int) parseLong(obj.get("count"), 0);

                    if (windowStart > 0 && count >= 0) {
                        IP_LIMIT.put(ip, new IpWindow(windowStart, count));
                    }
                }
            } catch (Exception e) {
                System.err.println("Impossible de charger ip.json (ignoré). Cause: " + e.getMessage());
            }
        }
    }

    private static void persistIpStore() {
        synchronized (FILE_LOCK) {
            StringBuilder sb = new StringBuilder();
            sb.append("{\n");
            int i = 0;
            for (Map.Entry<String, IpWindow> e : IP_LIMIT.entrySet()) {
                String ip = e.getKey();
                IpWindow w = e.getValue();

                if (i++ > 0) sb.append(",\n");
                sb.append("  \"").append(JsonMini.escape(ip)).append("\": ");
                sb.append("{");
                sb.append("\"windowStart\":").append(w.windowStartEpoch).append(",");
                sb.append("\"count\":").append(w.count);
                sb.append("}");
            }
            sb.append("\n}\n");
            writeAtomic(IP_FILE, sb.toString());
        }
    }

    private static void writeAtomic(Path file, String content) {
        try {
            Files.createDirectories(file.getParent());
            Path tmp = file.resolveSibling(file.getFileName().toString() + ".tmp");
            Files.writeString(tmp, content, StandardCharsets.UTF_8,
                    StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE);
            try {
                Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException e) {
            throw new UncheckedIOException(e);
        }
    }

    private static long parseLong(String s, long def) {
        if (s == null) return def;
        try { return Long.parseLong(s.trim()); }
        catch (NumberFormatException e) { return def; }
    }

    // =========================
    // Minimal JSON helper (no jar)
    // - fits ONLY our saved formats
    // =========================
    private static final class JsonMini {

        private static final Pattern STRING_FIELD =
                Pattern.compile("\"%s\"\\s*:\\s*\"(.*?)\"");
        private static final Pattern TOP_OBJECT_ENTRY =
                Pattern.compile("\"(.*?)\"\\s*:\\s*\\{(.*?)\\}", Pattern.DOTALL);

        static String getString(String json, String key) {
            Pattern p = Pattern.compile(String.format(STRING_FIELD.pattern(), Pattern.quote(key)), Pattern.DOTALL);
            Matcher m = p.matcher(json);
            if (!m.find()) return null;
            return unescape(m.group(1));
        }

        // Parse: { "k": { "a":"b", "x":1 }, "k2": {...} }
        static Map<String, Map<String, String>> parseTopObjectOfObjects(String json) {
            Map<String, Map<String, String>> out = new LinkedHashMap<>();
            Matcher m = TOP_OBJECT_ENTRY.matcher(json);
            while (m.find()) {
                String key = unescape(m.group(1));
                String inner = m.group(2);

                Map<String, String> innerMap = new HashMap<>();
                // strings: "field":"value"
                Matcher ms = Pattern.compile("\"(.*?)\"\\s*:\\s*\"(.*?)\"").matcher(inner);
                while (ms.find()) {
                    innerMap.put(unescape(ms.group(1)), unescape(ms.group(2)));
                }
                // numbers: "field":123
                Matcher mn = Pattern.compile("\"(.*?)\"\\s*:\\s*(\\d+)").matcher(inner);
                while (mn.find()) {
                    innerMap.put(unescape(mn.group(1)), mn.group(2));
                }

                out.put(key, innerMap);
            }
            return out;
        }

        static String escape(String s) {
            return s.replace("\\", "\\\\").replace("\"", "\\\"");
        }

        static String unescape(String s) {
            // minimal (enough for our data)
            return s.replace("\\\"", "\"").replace("\\\\", "\\");
        }
    }
}
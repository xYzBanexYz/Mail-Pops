package client;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;

import javax.mail.Folder;
import javax.mail.Session;
import javax.mail.Store;
import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.*;
import java.util.regex.Pattern;

public class ClientApp {

    // ====== CONFIG ======
    private static final String PKG_BASE_URL = "http://localhost:8080";
    private static final Path DATA_DIR = Paths.get("data");
    private static final Path ACCOUNTS_FILE = DATA_DIR.resolve("accounts.json");

    // ====== JSON ======
    private static final ObjectMapper MAPPER = new ObjectMapper()
            .enable(SerializationFeature.INDENT_OUTPUT);

    // ====== HTTP ======
    private static final HttpClient HTTP = HttpClient.newHttpClient();

    // ====== UI ======
    private JFrame frame;
    private CardLayout layout;
    private JPanel root;

    private JPanel pageSelect;
    private JPanel pageLoginPassword;
    private JPanel pageStep1;
    private JPanel pageStep2;
    private JPanel pageStep3;
    private JPanel pageMain;

    private AccountsStore store;
    private Account selectedAccount;

    // Select page
    private DefaultListModel<String> accountsListModel;
    private JList<String> accountsList;
    private JButton btnSelectLogin;

    // Login password page
    private JLabel loginEmailLabel;
    private JPasswordField loginPasswordField;
    private JLabel loginStatus;

    // Step 1
    private JTextField emailField;
    private JTextField otpField;
    private JLabel step1Status;

    // Step 2
    private JPasswordField passwordField;
    private JPasswordField passwordConfirmField;
    private JLabel step2Status;

    // Step 3
    private JPasswordField appPasswordField;
    private JLabel step3Status;

    // Main
    private JLabel mainLabel;

    // ====== MODELS ======
    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Account {
        public String email;
        public String privateKeyB64;     // from PKG
        public String passwordSha256;    // app login password hash
        public String appPassword;       // Gmail app password (plain for TP)
        public long createdAtEpoch;

        public boolean step1Done() { return email != null && privateKeyB64 != null && !privateKeyB64.isBlank(); }
        public boolean step2Done() { return passwordSha256 != null && !passwordSha256.isBlank(); }
        public boolean step3Done() { return appPassword != null && !appPassword.isBlank(); }
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class AccountsStore {
        public Map<String, Account> accounts = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
    }

    // ====== ENTRY ======
    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            try {
                new ClientApp().start();
            } catch (Exception e) {
                e.printStackTrace();
                JOptionPane.showMessageDialog(null, e.toString(), "Fatal error", JOptionPane.ERROR_MESSAGE);
            }
        });
    }

    private void start() throws Exception {
        Files.createDirectories(DATA_DIR);
        store = loadAccounts();

        frame = new JFrame("Client (TP)");
        frame.setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
        frame.setSize(640, 420);
        frame.setLocationRelativeTo(null);

        layout = new CardLayout();
        root = new JPanel(layout);

        pageSelect = buildSelectPage();
        pageLoginPassword = buildLoginPasswordPage();
        pageStep1 = buildStep1Page();
        pageStep2 = buildStep2Page();
        pageStep3 = buildStep3Page();
        pageMain  = buildMainPage();

        root.add(pageSelect, "select");
        root.add(pageLoginPassword, "loginpw");
        root.add(pageStep1, "step1");
        root.add(pageStep2, "step2");
        root.add(pageStep3, "step3");
        root.add(pageMain,  "main");

        frame.setContentPane(root);

        refreshAccountsList();
        showSelect();

        frame.setVisible(true);
    }

    // ====== NAV ======
    private void showSelect() {
        selectedAccount = null;
        accountsList.clearSelection();
        btnSelectLogin.setEnabled(false);
        layout.show(root, "select");
    }

    private void showLoginPassword(Account acc) {
        selectedAccount = acc;
        loginEmailLabel.setText(acc.email);
        loginPasswordField.setText("");
        loginStatus.setText(" ");
        layout.show(root, "loginpw");
    }

    private void showStep1Prefill(String email) {
        selectedAccount = null;
        emailField.setText(email == null ? "" : email);
        otpField.setText("");
        step1Status.setText(" ");
        layout.show(root, "step1");
    }

    private void showStep2For(Account acc) {
        selectedAccount = acc;
        passwordField.setText("");
        passwordConfirmField.setText("");
        step2Status.setText(" ");
        layout.show(root, "step2");
    }

    private void showStep3For(Account acc) {
        selectedAccount = acc;
        appPasswordField.setText("");
        step3Status.setText(" ");
        layout.show(root, "step3");
    }

    private void showMain(Account acc) {
        selectedAccount = acc;
        mainLabel.setText("<html><b>Connecté :</b> " + escapeHtml(acc.email) + "</html>");
        layout.show(root, "main");
    }

    /**
     * Règle:
     * - si compte incomplet -> reprend automatiquement le flow de création (step1/2/3)
     * - sinon -> page mot de passe (connexion)
     */
    private void routeAfterPick(Account acc) {
        if (acc == null) return;

        if (!acc.step1Done()) { showStep1Prefill(acc.email); return; }
        if (!acc.step2Done()) { showStep2For(acc); return; }
        if (!acc.step3Done()) { showStep3For(acc); return; }

        showLoginPassword(acc);
    }

    // ====== UI BUILDERS ======
    private JPanel buildBasePage() {
        JPanel p = new JPanel(new BorderLayout());
        p.setBorder(new EmptyBorder(18,18,18,18));
        return p;
    }

    private JPanel buildSelectPage() {
        JPanel p = buildBasePage();

        JPanel center = new JPanel(new BorderLayout(10, 10));
        center.setBorder(new EmptyBorder(20, 80, 20, 80)); // centre visuellement

        accountsListModel = new DefaultListModel<>();
        accountsList = new JList<>(accountsListModel);
        accountsList.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        accountsList.setVisibleRowCount(10);

        accountsList.addListSelectionListener(e -> {
            boolean selected = accountsList.getSelectedValue() != null;
            btnSelectLogin.setEnabled(selected);
        });

        center.add(new JScrollPane(accountsList), BorderLayout.CENTER);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.CENTER, 12, 8));
        btnSelectLogin = new JButton("Se connecter");
        btnSelectLogin.setEnabled(false);
        JButton btnCreate = new JButton("Créer un compte");

        btnSelectLogin.addActionListener(e -> {
            String email = accountsList.getSelectedValue();
            if (email == null) return;
            Account acc = store.accounts.get(email);
            routeAfterPick(acc);
        });

        btnCreate.addActionListener(e -> showStep1Prefill(""));

        buttons.add(btnSelectLogin);
        buttons.add(btnCreate);

        center.add(buttons, BorderLayout.SOUTH);
        p.add(center, BorderLayout.CENTER);

        return p;
    }

    private JPanel buildLoginPasswordPage() {
        JPanel p = buildBasePage();

        JPanel center = new JPanel();
        center.setLayout(new BoxLayout(center, BoxLayout.Y_AXIS));
        center.setBorder(new EmptyBorder(30, 120, 30, 120));

        JLabel title = new JLabel("Connexion");
        title.setAlignmentX(Component.CENTER_ALIGNMENT);
        title.setFont(title.getFont().deriveFont(Font.BOLD, 18f));

        loginEmailLabel = new JLabel("");
        loginEmailLabel.setAlignmentX(Component.CENTER_ALIGNMENT);

        center.add(title);
        center.add(Box.createVerticalStrut(10));
        center.add(loginEmailLabel);
        center.add(Box.createVerticalStrut(18));

        loginPasswordField = new JPasswordField();
        loginPasswordField.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));
        center.add(loginPasswordField);

        center.add(Box.createVerticalStrut(10));

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.CENTER, 12, 8));
        JButton btnLogin = new JButton("Valider");
        JButton btnBack = new JButton("Retour");

        loginStatus = new JLabel(" ");
        loginStatus.setAlignmentX(Component.CENTER_ALIGNMENT);

        btnBack.addActionListener(e -> showSelect());

        btnLogin.addActionListener(e -> {
            if (selectedAccount == null) return;

            String entered = new String(loginPasswordField.getPassword());
            if (entered.isBlank()) {
                loginStatus.setText("Mot de passe requis.");
                return;
            }

            String hash = sha256Hex(entered);
            if (!hash.equalsIgnoreCase(selectedAccount.passwordSha256)) {
                loginStatus.setText("Mot de passe incorrect.");
                return;
            }

            // Vérif IMAP (si app password a changé)
            loginStatus.setText("Vérification messagerie...");
            async(() -> {
                boolean ok = tryImapLogin(selectedAccount.email, selectedAccount.appPassword);
                ui(() -> {
                    if (ok) showMain(selectedAccount);
                    else showStep3For(selectedAccount);
                });
            });
        });

        buttons.add(btnLogin);
        buttons.add(btnBack);

        center.add(buttons);
        center.add(Box.createVerticalStrut(10));
        center.add(loginStatus);

        p.add(center, BorderLayout.CENTER);
        return p;
    }

    private JPanel buildStep1Page() {
        JPanel p = buildBasePage();

        JPanel center = new JPanel();
        center.setLayout(new BoxLayout(center, BoxLayout.Y_AXIS));
        center.setBorder(new EmptyBorder(20, 100, 20, 100));

        JLabel title = new JLabel("Créer un compte — Email");
        title.setAlignmentX(Component.CENTER_ALIGNMENT);
        title.setFont(title.getFont().deriveFont(Font.BOLD, 18f));

        emailField = new JTextField();
        emailField.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));

        JButton btnSend = new JButton("Envoyer code");
        JButton btnConfirm = new JButton("Confirmer");
        JButton btnBack = new JButton("Retour");

        otpField = new JTextField();
        otpField.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));

        step1Status = new JLabel(" ");
        step1Status.setAlignmentX(Component.CENTER_ALIGNMENT);

        btnSend.addActionListener(e -> {
            String email = emailField.getText().trim();
            if (!isValidEmail(email)) {
                step1Status.setText("Email invalide.");
                return;
            }

            Account existing = store.accounts.get(email);
            if (existing != null && existing.step1Done()) {
                // compte déjà créé -> on route (reprend éventuellement step2/3)
                routeAfterPick(existing);
                return;
            }

            if (existing == null) {
                Account acc = new Account();
                acc.email = email;
                acc.createdAtEpoch = Instant.now().getEpochSecond();
                store.accounts.put(email, acc);
                saveAccounts(store);
                refreshAccountsList();
            }

            step1Status.setText("Envoi du code...");
            async(() -> {
                try {
                    pkgRequestOtp(email);
                    ui(() -> step1Status.setText("Code envoyé."));
                } catch (Exception ex) {
                    ui(() -> step1Status.setText("Erreur: " + ex.getMessage()));
                }
            });
        });

        btnConfirm.addActionListener(e -> {
            String email = emailField.getText().trim();
            String code = otpField.getText().trim();

            if (!isValidEmail(email) || !code.matches("^\\d{6}$")) {
                step1Status.setText("Email / code invalide.");
                return;
            }

            Account acc = store.accounts.get(email);
            if (acc == null) {
                step1Status.setText("Envoyez d'abord un code.");
                return;
            }

            step1Status.setText("Validation...");
            async(() -> {
                try {
                    String privateKeyB64 = pkgConfirmOtp(email, code);
                    acc.privateKeyB64 = privateKeyB64;
                    store.accounts.put(email, acc);
                    saveAccounts(store);
                    ui(() -> showStep2For(acc));
                } catch (Exception ex) {
                    ui(() -> step1Status.setText("Erreur: " + ex.getMessage()));
                }
            });
        });

        btnBack.addActionListener(e -> showSelect());

        center.add(title);
        center.add(Box.createVerticalStrut(16));
        center.add(new JLabel("Email"));
        center.add(emailField);
        center.add(Box.createVerticalStrut(8));
        center.add(btnSend);
        center.add(Box.createVerticalStrut(16));
        center.add(new JLabel("Code (6 chiffres)"));
        center.add(otpField);
        center.add(Box.createVerticalStrut(8));
        center.add(btnConfirm);
        center.add(Box.createVerticalStrut(12));
        center.add(step1Status);
        center.add(Box.createVerticalStrut(14));
        center.add(btnBack);

        p.add(center, BorderLayout.CENTER);
        return p;
    }

    private JPanel buildStep2Page() {
        JPanel p = buildBasePage();

        JPanel center = new JPanel();
        center.setLayout(new BoxLayout(center, BoxLayout.Y_AXIS));
        center.setBorder(new EmptyBorder(20, 100, 20, 100));

        JLabel title = new JLabel("Créer un compte — Mot de passe");
        title.setAlignmentX(Component.CENTER_ALIGNMENT);
        title.setFont(title.getFont().deriveFont(Font.BOLD, 18f));

        passwordField = new JPasswordField();
        passwordField.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));
        passwordConfirmField = new JPasswordField();
        passwordConfirmField.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));

        JButton btnSet = new JButton("Valider");
        JButton btnBack = new JButton("Retour");

        step2Status = new JLabel(" ");
        step2Status.setAlignmentX(Component.CENTER_ALIGNMENT);

        btnSet.addActionListener(e -> {
            if (selectedAccount == null) return;

            String p1 = new String(passwordField.getPassword());
            String p2 = new String(passwordConfirmField.getPassword());

            String msg = checkPasswordPolicy(p1);
            if (msg != null) { step2Status.setText(msg); return; }
            if (!p1.equals(p2)) { step2Status.setText("Confirmation différente."); return; }

            selectedAccount.passwordSha256 = sha256Hex(p1);
            store.accounts.put(selectedAccount.email, selectedAccount);
            saveAccounts(store);

            showStep3For(selectedAccount);
        });

        btnBack.addActionListener(e -> showSelect());

        center.add(title);
        center.add(Box.createVerticalStrut(16));
        center.add(new JLabel("Mot de passe"));
        center.add(passwordField);
        center.add(Box.createVerticalStrut(10));
        center.add(new JLabel("Confirmer"));
        center.add(passwordConfirmField);
        center.add(Box.createVerticalStrut(12));
        center.add(btnSet);
        center.add(Box.createVerticalStrut(12));
        center.add(step2Status);
        center.add(Box.createVerticalStrut(14));
        center.add(btnBack);

        p.add(center, BorderLayout.CENTER);
        return p;
    }

    private JPanel buildStep3Page() {
        JPanel p = buildBasePage();

        JPanel center = new JPanel();
        center.setLayout(new BoxLayout(center, BoxLayout.Y_AXIS));
        center.setBorder(new EmptyBorder(20, 100, 20, 100));

        JLabel title = new JLabel("Créer un compte — App Password Gmail");
        title.setAlignmentX(Component.CENTER_ALIGNMENT);
        title.setFont(title.getFont().deriveFont(Font.BOLD, 18f));

        appPasswordField = new JPasswordField();
        appPasswordField.setMaximumSize(new Dimension(Integer.MAX_VALUE, 30));

        JButton btnTestSave = new JButton("Valider");
        JButton btnBack = new JButton("Retour");

        step3Status = new JLabel(" ");
        step3Status.setAlignmentX(Component.CENTER_ALIGNMENT);

        btnTestSave.addActionListener(e -> {
            if (selectedAccount == null) return;

            String ap = new String(appPasswordField.getPassword()).replaceAll("\\s+", "");
            if (ap.length() < 16) {
                step3Status.setText("App Password trop court.");
                return;
            }

            step3Status.setText("Test messagerie...");
            async(() -> {
                boolean ok = tryImapLogin(selectedAccount.email, ap);
                ui(() -> {
                    if (!ok) {
                        step3Status.setText("Accès IMAP impossible.");
                        return;
                    }
                    selectedAccount.appPassword = ap;
                    store.accounts.put(selectedAccount.email, selectedAccount);
                    saveAccounts(store);
                    showMain(selectedAccount);
                });
            });
        });

        btnBack.addActionListener(e -> showSelect());

        center.add(title);
        center.add(Box.createVerticalStrut(16));
        center.add(new JLabel("App Password"));
        center.add(appPasswordField);
        center.add(Box.createVerticalStrut(12));
        center.add(btnTestSave);
        center.add(Box.createVerticalStrut(12));
        center.add(step3Status);
        center.add(Box.createVerticalStrut(14));
        center.add(btnBack);

        p.add(center, BorderLayout.CENTER);
        return p;
    }

    private JPanel buildMainPage() {
        JPanel p = buildBasePage();

        JPanel center = new JPanel();
        center.setLayout(new BoxLayout(center, BoxLayout.Y_AXIS));
        center.setBorder(new EmptyBorder(40, 100, 40, 100));

        JLabel title = new JLabel("Accueil");
        title.setAlignmentX(Component.CENTER_ALIGNMENT);
        title.setFont(title.getFont().deriveFont(Font.BOLD, 18f));

        mainLabel = new JLabel(" ");
        mainLabel.setAlignmentX(Component.CENTER_ALIGNMENT);

        JButton btnLogout = new JButton("Déconnexion");
        btnLogout.setAlignmentX(Component.CENTER_ALIGNMENT);
        btnLogout.addActionListener(e -> showSelect());

        center.add(title);
        center.add(Box.createVerticalStrut(18));
        center.add(mainLabel);
        center.add(Box.createVerticalStrut(22));
        center.add(btnLogout);

        p.add(center, BorderLayout.CENTER);
        return p;
    }

    // ====== PKG API ======
    private static void pkgRequestOtp(String email) throws Exception {
        String body = "email=" + URLEncoder.encode(email, StandardCharsets.UTF_8);
        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(PKG_BASE_URL + "/auth/request"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        HttpResponse<String> resp = HTTP.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        if (resp.statusCode() != 200) {
            throw new RuntimeException("PKG " + resp.statusCode() + ": " + resp.body());
        }
    }

    private static String pkgConfirmOtp(String email, String code) throws Exception {
        String body = "email=" + URLEncoder.encode(email, StandardCharsets.UTF_8) +
                "&code=" + URLEncoder.encode(code, StandardCharsets.UTF_8);

        HttpRequest req = HttpRequest.newBuilder()
                .uri(URI.create(PKG_BASE_URL + "/auth/confirm"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body))
                .build();

        HttpResponse<String> resp = HTTP.send(req, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        if (resp.statusCode() != 200) {
            throw new RuntimeException("PKG " + resp.statusCode() + ": " + resp.body());
        }

        String pk = extractJsonString(resp.body(), "privateKey");
        if (pk == null || pk.isBlank()) throw new RuntimeException("Réponse PKG invalide");
        return pk;
    }

    private static String extractJsonString(String json, String key) {
        String needle = "\"" + key + "\"";
        int i = json.indexOf(needle);
        if (i < 0) return null;
        int colon = json.indexOf(':', i);
        if (colon < 0) return null;
        int firstQuote = json.indexOf('"', colon + 1);
        if (firstQuote < 0) return null;
        int secondQuote = json.indexOf('"', firstQuote + 1);
        while (secondQuote > 0 && json.charAt(secondQuote - 1) == '\\') {
            secondQuote = json.indexOf('"', secondQuote + 1);
        }
        if (secondQuote < 0) return null;
        return json.substring(firstQuote + 1, secondQuote).replace("\\\"", "\"").replace("\\\\", "\\");
    }

    // ====== MAIL CHECK (IMAP) ======
    private static boolean tryImapLogin(String email, String appPassword) {
        try {
            Properties props = new Properties();
            props.put("mail.store.protocol", "imaps");
            props.put("mail.imaps.host", "imap.gmail.com");
            props.put("mail.imaps.port", "993");
            props.put("mail.imaps.ssl.enable", "true");
            props.put("mail.imaps.connectiontimeout", "8000");
            props.put("mail.imaps.timeout", "8000");

            Session session = Session.getInstance(props);
            Store store = session.getStore("imaps");
            store.connect("imap.gmail.com", email, appPassword);

            Folder inbox = store.getFolder("INBOX");
            inbox.open(Folder.READ_ONLY);
            inbox.close(false);

            store.close();
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    // ====== PASSWORD POLICY ======
    private static String checkPasswordPolicy(String p) {
        if (p == null) return "Mot de passe vide.";
        if (p.length() < 10) return "Minimum 10 caractères.";
        if (!Pattern.compile("[A-Z]").matcher(p).find()) return "1 majuscule minimum.";
        if (!Pattern.compile("[a-z]").matcher(p).find()) return "1 minuscule minimum.";
        if (!Pattern.compile("\\d").matcher(p).find()) return "1 chiffre minimum.";
        if (!Pattern.compile("[^A-Za-z0-9]").matcher(p).find()) return "1 caractère spécial minimum.";
        return null;
    }

    // ====== HASH ======
    private static String sha256Hex(String s) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] dig = md.digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(dig.length * 2);
            for (byte b : dig) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    // ====== ACCOUNTS JSON ======
    private static AccountsStore loadAccounts() {
        try {
            if (!Files.exists(ACCOUNTS_FILE)) return new AccountsStore();
            byte[] bytes = Files.readAllBytes(ACCOUNTS_FILE);
            AccountsStore st = MAPPER.readValue(bytes, AccountsStore.class);
            if (st.accounts == null) st.accounts = new TreeMap<>(String.CASE_INSENSITIVE_ORDER);
            return st;
        } catch (Exception e) {
            return new AccountsStore();
        }
    }

    private static void saveAccounts(AccountsStore st) {
        synchronized (AccountsStore.class) {
            try {
                Files.createDirectories(ACCOUNTS_FILE.getParent());
                Path tmp = ACCOUNTS_FILE.resolveSibling(ACCOUNTS_FILE.getFileName() + ".tmp");
                byte[] bytes = MAPPER.writeValueAsBytes(st);
                Files.write(tmp, bytes, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
                try {
                    Files.move(tmp, ACCOUNTS_FILE, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
                } catch (AtomicMoveNotSupportedException e) {
                    Files.move(tmp, ACCOUNTS_FILE, StandardCopyOption.REPLACE_EXISTING);
                }
            } catch (IOException e) {
                throw new RuntimeException(e);
            }
        }
    }

    private void refreshAccountsList() {
        accountsListModel.clear();
        for (String email : store.accounts.keySet()) {
            accountsListModel.addElement(email);
        }
    }

    // ====== UTIL ======
    private static boolean isValidEmail(String email) {
        if (email == null) return false;
        return EMAIL_RE.matcher(email.trim()).matches();
    }

    private static final Pattern EMAIL_RE =
            Pattern.compile("^[A-Z0-9._%+-]+@[A-Z0-9.-]+\\.[A-Z]{2,}$", Pattern.CASE_INSENSITIVE);

    private static void async(Runnable r) {
        new Thread(r, "client-bg").start();
    }

    private static void ui(Runnable r) {
        SwingUtilities.invokeLater(r);
    }

    private static String escapeHtml(String s) {
        return s == null ? "" : s.replace("&","&amp;").replace("<","&lt;").replace(">","&gt;");
    }
}
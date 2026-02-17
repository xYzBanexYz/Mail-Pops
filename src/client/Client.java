package client;

import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;
import org.json.JSONObject;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.Scanner;

public class Client {

    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 128;

    // ===== SHA-256 =====
    private static byte[] sha256(byte[] input) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(input);
    }

    // ===== Dérive AES key depuis Element GT =====
    private static SecretKey deriveAESKey(Element K) throws Exception {
        byte[] keyBytes = sha256(K.toBytes());
        return new SecretKeySpec(keyBytes, "AES");
    }

    // ===== AES-GCM Déchiffrement =====
    private static byte[] decryptAES(byte[] iv, byte[] ciphertext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.DECRYPT_MODE, key, spec);
        return cipher.doFinal(ciphertext);
    }

    // ===== AES-GCM Chiffrement =====
    private static byte[][] encryptAES(byte[] plaintext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        byte[] iv = new byte[GCM_IV_LENGTH];
        new java.security.SecureRandom().nextBytes(iv);
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_LENGTH, iv);
        cipher.init(Cipher.ENCRYPT_MODE, key, spec);
        byte[] ciphertext = cipher.doFinal(plaintext);
        return new byte[][]{iv, ciphertext};
    }

    // ===== HTTP GET =====
    private static String httpGet(String urlStr) throws Exception {
        URL url = new URL(urlStr);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("GET");

        InputStream in = conn.getInputStream();
        Scanner sc = new Scanner(in).useDelimiter("\\A");
        String result = sc.hasNext() ? sc.next() : "";
        sc.close();
        return result;
    }

    public static void main(String[] args) throws Exception {

        String pkgUrl = "http://localhost:8080";

        // =========================
        // 1️⃣ Récupérer params publics
        // =========================
        String paramsJson = httpGet(pkgUrl + "/params");
        JSONObject params = new JSONObject(paramsJson);

        // Init pairing
        Pairing pairing = PairingFactory.getPairing("a.properties");

        // Restaurer P et Ppub depuis Base64
        Element P = pairing.getG1().newElementFromBytes(
                Base64.getDecoder().decode(params.getString("P"))).getImmutable();
        Element Ppub = pairing.getG1().newElementFromBytes(
                Base64.getDecoder().decode(params.getString("Ppub"))).getImmutable();

        System.out.println("Paramètres publics récupérés.");

        // =========================
        // 2️⃣ Récupérer sa clé privée
        // =========================
        String myID = "bob@mail.com";
        String privateKeyJson = httpGet(pkgUrl + "/privateKey?id=" + myID);
        JSONObject privKeyObj = new JSONObject(privateKeyJson);

        Element dMe = pairing.getG1().newElementFromBytes(
                Base64.getDecoder().decode(privKeyObj.getString("privateKey"))).getImmutable();

        System.out.println("Clé privée reçue pour " + myID);

        // =========================
        // 3️⃣ Chiffrement vers un destinataire (Alice -> Bob)
        // =========================
        String destID = "bob@mail.com";
        Element Qdest = pairing.getG1().newElement()
                .setFromHash(destID.getBytes(), 0, destID.length())
                .getImmutable();

        Element r = pairing.getZr().newRandomElement().getImmutable();
        Element C1 = P.duplicate().powZn(r).getImmutable();

        Element g = pairing.pairing(Qdest, Ppub).getImmutable();
        Element K = g.duplicate().powZn(r).getImmutable();

        SecretKey aesKey = deriveAESKey(K);

        String message = "HELLO BOB - message chiffré par Alice";
        byte[][] encrypted = encryptAES(message.getBytes(StandardCharsets.UTF_8), aesKey);
        byte[] iv = encrypted[0];
        byte[] C2 = encrypted[1];

        System.out.println("Message chiffré par Alice.");

        // =========================
        // 4️⃣ Déchiffrement par Bob
        // =========================
        Element K2 = pairing.pairing(dMe, C1).getImmutable();
        SecretKey aesKey2 = deriveAESKey(K2);

        byte[] decrypted = decryptAES(iv, C2, aesKey2);
        String decryptedMessage = new String(decrypted, StandardCharsets.UTF_8);

        System.out.println("Message déchiffré par Bob : " + decryptedMessage);
    }
}

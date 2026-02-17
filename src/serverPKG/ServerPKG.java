package serverPKG;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import it.unisa.dia.gas.jpbc.*;
import it.unisa.dia.gas.plaf.jpbc.pairing.PairingFactory;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.URI;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class ServerPKG {

    private static Pairing pairing;
    private static Element P;
    private static Element s;
    private static Element Ppub;

    public static void main(String[] args) throws Exception {

        System.out.println("=== Initialisation du PKG ===");

        pairing = PairingFactory.getPairing("params/curves/a.properties");

        P = pairing.getG1().newRandomElement().getImmutable();
        s = pairing.getZr().newRandomElement().getImmutable();
        Ppub = P.duplicate().powZn(s).getImmutable();
        
        System.out.println("P : " + P);
        System.out.println("S : " + s);
        System.out.println("Ppub : " + Ppub);
        
        System.out.println("PKG prêt.");

        HttpServer server = HttpServer.create(new InetSocketAddress(8080), 0);

        server.createContext("/params", ServerPKG::handleParams);
        server.createContext("/privateKey", ServerPKG::handlePrivateKey);

        server.setExecutor(null);
        server.start();

        System.out.println("Serveur PKG lancé sur http://localhost:8080");
    }

    // ========================
    // Endpoint: GET /params
    // ========================
    private static void handleParams(HttpExchange exchange) throws IOException {

        if (!exchange.getRequestMethod().equalsIgnoreCase("GET")) {
            exchange.sendResponseHeaders(405, -1);
            return;
        }

        String response =
                "{\n" +
                        "\"P\": \"" + Base64.getEncoder().encodeToString(P.toBytes()) + "\",\n" +
                        "\"Ppub\": \"" + Base64.getEncoder().encodeToString(Ppub.toBytes()) + "\"\n" +
                        "}";

        sendResponse(exchange, response);
    }

    // ========================
    // Endpoint: GET /privateKey?id=xxx
    // ========================
    private static void handlePrivateKey(HttpExchange exchange) throws IOException {

        if (!exchange.getRequestMethod().equalsIgnoreCase("GET")) {
            exchange.sendResponseHeaders(405, -1);
            return;
        }

        Map<String, String> params = queryToMap(exchange.getRequestURI());

        String id = params.get("id");

        if (id == null) {
            sendResponse(exchange, "Missing parameter: id");
            return;
        }

        // Hash vers point de courbe
        Element Q = pairing.getG1().newElement()
                .setFromHash(id.getBytes(), 0, id.length())
                .getImmutable();

        // Clé privée = s * Q
        Element d = Q.duplicate().powZn(s).getImmutable();

        String response =
                "{\n" +
                        "\"id\": \"" + id + "\",\n" +
                        "\"privateKey\": \"" +
                        Base64.getEncoder().encodeToString(d.toBytes()) + "\"\n" +
                        "}";

        sendResponse(exchange, response);
    }

    // ========================
    // Utils HTTP
    // ========================
    private static void sendResponse(HttpExchange exchange, String response) throws IOException {
        exchange.sendResponseHeaders(200, response.length());
        OutputStream os = exchange.getResponseBody();
        os.write(response.getBytes());
        os.close();
    }

    private static Map<String, String> queryToMap(URI uri) {
        Map<String, String> result = new HashMap<>();
        String query = uri.getQuery();

        if (query == null) return result;

        for (String param : query.split("&")) {
            String[] entry = param.split("=");
            if (entry.length > 1)
                result.put(entry[0], entry[1]);
        }
        return result;
    }
}

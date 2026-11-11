package com.auth0.jwt;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.TimeUnit;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;

/**
 * Tests for .github/scripts/publish-signing-key.sh, the script the release pipeline runs to
 * publish the signing key to keys.openpgp.org before the artifacts are published.
 *
 * <p>Every test talks to a local HTTP server. The tests must never reach the real keyserver,
 * since uploading a key there cannot be undone.</p>
 */
public class PublishSigningKeyScriptTest {

    private static final String FINGERPRINT = "EB7023FDA6D951AFD6929755F6641015B2AA7749";

    private final List<RecordedRequest> requests = Collections.synchronizedList(new ArrayList<>());
    private HttpServer server;
    private Path script;
    private Path keyFile;
    private Path gpgHome;

    @Before
    public void setUp() throws Exception {
        script = Paths.get("..", ".github", "scripts", "publish-signing-key.sh").toAbsolutePath().normalize();
        keyFile = Paths.get("src", "test", "resources", "publish-signing-key", "test-key.asc")
                .toAbsolutePath().normalize();
        gpgHome = Files.createTempDirectory("publish-signing-key-gnupg");
    }

    @After
    public void tearDown() throws IOException {
        if (server != null) {
            server.stop(0);
        }
        deleteRecursively(gpgHome);
    }

    @Test
    public void publishesKeyAndConfirmsItIsRetrievable() throws Exception {
        startServer(true);

        Result result = runScript("--key-file", keyFile.toString());

        assertThat(result.output, result.exitCode, is(0));

        RecordedRequest upload = onlyRequest("POST", "/vks/v1/upload");
        assertThat(upload.contentType, containsString("application/json"));
        assertThat(upload.body, containsString("\"keytext\""));
        assertThat(upload.body, containsString("BEGIN PGP PUBLIC KEY BLOCK"));

        RecordedRequest lookup = onlyRequest("GET", "/vks/v1/by-fingerprint/" + FINGERPRINT);
        assertThat(lookup.body, is(""));
    }

    @Test
    public void reportsFingerprintItPublishes() throws Exception {
        startServer(true);

        Result result = runScript("--key-file", keyFile.toString());

        assertThat(result.output, result.exitCode, is(0));
        assertThat(result.output, containsString(FINGERPRINT));
    }

    @Test
    public void failsWhenKeyIsNotRetrievableAfterUpload() throws Exception {
        startServer(false);

        Result result = runScript("--key-file", keyFile.toString(), "--timeout", "0");

        assertThat(result.output, result.exitCode, is(not(0)));
        assertThat(result.output, containsString("is not retrievable from"));
    }

    @Test
    public void failsWhenKeyFileIsMissing() throws Exception {
        startServer(true);

        Result result = runScript("--key-file", keyFile.resolveSibling("missing.asc").toString());

        assertThat(result.output, result.exitCode, is(not(0)));
        assertThat(result.output, containsString("key file not found"));
        assertThat(requests.isEmpty(), is(true));
    }

    @Test
    public void failsWhenKeyFileIsNotAKey() throws Exception {
        startServer(true);
        Path notAKey = Files.createTempFile("not-a-key", ".asc");
        Files.write(notAKey, "not a key".getBytes(StandardCharsets.UTF_8));

        Result result = runScript("--key-file", notAKey.toString());

        assertThat(result.output, result.exitCode, is(not(0)));
        assertThat(result.output, containsString("could not read a key fingerprint"));
        assertThat(requests.isEmpty(), is(true));
    }

    @Test
    public void exportsPublicKeyFromSigningKey() throws Exception {
        startServer(true);

        // A public key is enough to exercise the export path: importing it into the
        // ephemeral keyring and exporting it again must produce the same key material.
        String armoredKey = new String(Files.readAllBytes(keyFile), StandardCharsets.UTF_8);
        Result result = runScript(Collections.singletonList("SIGNING_KEY=" + armoredKey));

        assertThat(result.output, result.exitCode, is(0));
        RecordedRequest upload = onlyRequest("POST", "/vks/v1/upload");
        assertThat(upload.body, containsString("BEGIN PGP PUBLIC KEY BLOCK"));
        onlyRequest("GET", "/vks/v1/by-fingerprint/" + FINGERPRINT);
    }

    @Test
    public void failsWhenNeitherKeyFileNorSigningKeyIsProvided() throws Exception {
        startServer(true);

        Result result = runScript(Collections.<String>emptyList());

        assertThat(result.output, result.exitCode, is(not(0)));
        assertThat(result.output, containsString("provide --key-file or set SIGNING_KEY"));
        assertThat(requests.isEmpty(), is(true));
    }

    @Test
    public void defaultsToKeysOpenPgpOrg() throws Exception {
        String contents = new String(Files.readAllBytes(script), StandardCharsets.UTF_8);

        assertThat(contents, containsString("DEFAULT_KEYSERVER=\"https://keys.openpgp.org\""));
        assertThat(contents, containsString("/vks/v1/upload"));
    }

    @Test
    public void uploadsThroughTheVksApiRatherThanGpgSendKeys() throws Exception {
        List<String> commands = new ArrayList<>();
        for (String line : Files.readAllLines(script, StandardCharsets.UTF_8)) {
            String trimmed = line.trim();
            if (!trimmed.isEmpty() && !trimmed.startsWith("#")) {
                commands.add(trimmed);
            }
        }

        // gpg --send-keys and curl -T do not work against keys.openpgp.org; its VKS API does.
        for (String command : commands) {
            assertThat(command, not(containsString("--send-keys")));
        }
    }

    private void startServer(final boolean keyRetrievable) throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/vks/v1/upload", new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                record(exchange);
                respond(exchange, 200, "{\"key_fpr\":\"" + FINGERPRINT + "\"}");
            }
        });
        server.createContext("/vks/v1/by-fingerprint/" + FINGERPRINT, new HttpHandler() {
            @Override
            public void handle(HttpExchange exchange) throws IOException {
                record(exchange);
                if (keyRetrievable) {
                    respond(exchange, 200, "-----BEGIN PGP PUBLIC KEY BLOCK-----\n");
                } else {
                    respond(exchange, 404, "No key found");
                }
            }
        });
        server.start();
    }

    private void record(HttpExchange exchange) throws IOException {
        requests.add(new RecordedRequest(
                exchange.getRequestMethod(),
                exchange.getRequestURI().getPath(),
                exchange.getRequestHeaders().getFirst("Content-Type"),
                readAll(exchange.getRequestBody())));
    }

    private String baseUrl() {
        return "http://127.0.0.1:" + server.getAddress().getPort();
    }

    private Result runScript(String... args) throws Exception {
        return runScript(Collections.<String>emptyList(), args);
    }

    private Result runScript(List<String> extraEnv, String... args) throws Exception {
        List<String> command = new ArrayList<>();
        command.add("bash");
        command.add(script.toString());
        Collections.addAll(command, args);
        // Always point the script at the local server; it must never reach the real keyserver.
        command.add("--keyserver");
        command.add(baseUrl());

        ProcessBuilder builder = new ProcessBuilder(command);
        builder.redirectErrorStream(true);
        builder.environment().remove("SIGNING_KEY");
        builder.environment().put("GNUPGHOME", gpgHome.toString());
        for (String entry : extraEnv) {
            int separator = entry.indexOf('=');
            builder.environment().put(entry.substring(0, separator), entry.substring(separator + 1));
        }

        Process process = builder.start();
        String output = readAll(process.getInputStream());
        if (!process.waitFor(60, TimeUnit.SECONDS)) {
            process.destroyForcibly();
            throw new AssertionError("script did not finish in time: " + output);
        }
        return new Result(process.exitValue(), output);
    }

    private RecordedRequest onlyRequest(String method, String path) {
        for (RecordedRequest request : requests) {
            if (request.method.equals(method) && request.path.equals(path)) {
                return request;
            }
        }
        throw new AssertionError("no " + method + " " + path + " request was made; saw " + requests);
    }

    private static String readAll(InputStream inputStream) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] chunk = new byte[1024];
        int read;
        while ((read = inputStream.read(chunk)) != -1) {
            buffer.write(chunk, 0, read);
        }
        return new String(buffer.toByteArray(), StandardCharsets.UTF_8);
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream outputStream = exchange.getResponseBody()) {
            outputStream.write(bytes);
        }
    }

    private static void deleteRecursively(Path path) throws IOException {
        if (path == null || !Files.exists(path)) {
            return;
        }
        Files.walk(path)
                .sorted(Collections.reverseOrder())
                .forEach(candidate -> {
                    try {
                        Files.deleteIfExists(candidate);
                    } catch (IOException ignored) {
                        // Best effort cleanup of the temporary keyring.
                    }
                });
    }

    private static final class RecordedRequest {
        private final String method;
        private final String path;
        private final String contentType;
        private final String body;

        private RecordedRequest(String method, String path, String contentType, String body) {
            this.method = method;
            this.path = path;
            this.contentType = contentType;
            this.body = body;
        }

        @Override
        public String toString() {
            return method + " " + path;
        }
    }

    private static final class Result {
        private final int exitCode;
        private final String output;

        private Result(int exitCode, String output) {
            this.exitCode = exitCode;
            this.output = output;
        }
    }
}

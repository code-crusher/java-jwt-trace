package com.auth0.jwt.impl;

import com.auth0.jwt.RegisteredClaims;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.Payload;
import tools.jackson.core.JacksonException;
import tools.jackson.core.JsonParser;
import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.DeserializationContext;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.deser.std.StdDeserializer;

import java.time.DateTimeException;
import java.time.Instant;
import java.util.*;

/**
 * Jackson deserializer implementation for converting from JWT Payload parts.
 * <p>
 * This class is thread-safe.
 *
 * @see JWTParser
 */
class PayloadDeserializer extends StdDeserializer<Payload> {

    PayloadDeserializer() {
        super(Payload.class);
    }

    @Override
    public Payload deserialize(JsonParser p, DeserializationContext ctxt) throws JacksonException {
        Map<String, JsonNode> tree = ctxt.readValue(p, new TypeReference<Map<String, JsonNode>>() {
        });
        if (tree == null) {
            throw new JWTDecodeException("Parsing the Payload's JSON resulted on a Null map");
        }

        String issuer = getString(tree, RegisteredClaims.ISSUER);
        String subject = getString(tree, RegisteredClaims.SUBJECT);
        List<String> audience = getStringOrArray(ctxt, tree, RegisteredClaims.AUDIENCE);
        Instant expiresAt = getInstantFromSeconds(tree, RegisteredClaims.EXPIRES_AT);
        Instant notBefore = getInstantFromSeconds(tree, RegisteredClaims.NOT_BEFORE);
        Instant issuedAt = getInstantFromSeconds(tree, RegisteredClaims.ISSUED_AT);
        String jwtId = getString(tree, RegisteredClaims.JWT_ID);

        return new PayloadImpl(issuer, subject, audience, expiresAt, notBefore, issuedAt, jwtId, tree);
    }

    List<String> getStringOrArray(DeserializationContext ctxt, Map<String, JsonNode> tree, String claimName)
            throws JWTDecodeException {
        JsonNode node = tree.get(claimName);
        if (node == null || node.isNull() || !(node.isArray() || node.isString())) {
            return null;
        }
        if (node.isString()) {
            return Collections.singletonList(node.asString());
        }

        List<String> list = new ArrayList<>(node.size());
        for (int i = 0; i < node.size(); i++) {
            try {
                list.add(ctxt.readTreeAsValue(node.get(i), String.class));
            } catch (JacksonException e) {
                throw new JWTDecodeException("Couldn't map the Claim's array contents to String", e);
            }
        }
        return list;
    }

    Instant getInstantFromSeconds(Map<String, JsonNode> tree, String claimName) {
        JsonNode node = tree.get(claimName);
        if (node == null || node.isNull()) {
            return null;
        }
        // A NumericDate per RFC 7519 is a JSON number and may be written in scientific notation
        // (for example 1.7e9). Split the two failure modes so the thrown error is accurate: a
        // genuinely non-numeric value, versus a numeric value that is out of the range a long can
        // hold (such as 1.733162101e+26). Previously both produced "non-numeric date value", which
        // is wrong for the second case and made large/scientific values look unsupported.
        if (!node.isNumber()) {
            throw new JWTDecodeException(
                    String.format("The claim '%s' contained a non-numeric date value.", claimName));
        }
        if (!node.canConvertToLong()) {
            throw new JWTDecodeException(String.format(
                    "The claim '%s' value (%s) is out of the range representable as a NumericDate.",
                    claimName, node.asString()));
        }
        long epochSecond = node.asLong();
        try {
            return Instant.ofEpochSecond(epochSecond);
        } catch (DateTimeException e) {
            throw new JWTDecodeException(String.format(
                    "The claim '%s' value (%s) is outside the valid Instant epoch-second range.",
                    claimName, epochSecond), e);
        }
    }

    String getString(Map<String, JsonNode> tree, String claimName) {
        JsonNode node = tree.get(claimName);
        if (node == null || node.isNull()) {
            return null;
        }
        // An empty default reproduces Jackson 2's asText(null): containers coerce to "".
        return node.asString("");
    }
}

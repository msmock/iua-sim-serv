package org.fnm.helper;

import com.auth0.jwt.algorithms.Algorithm;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.ParseException;

public class AlgorithmHelper {

    public static Algorithm loadECPrivateKey() throws ParseException, IOException, JOSEException {
        String privateKeyAsString = Files.readString(Paths.get("signature-keys/JWK-EC-pair.json"));
        JWK privateJWK = JWK.parse(privateKeyAsString);
        ECKey privateKey = privateJWK.toECKey();
        return Algorithm.ECDSA256(privateKey.toECPrivateKey());
    }

    public static Algorithm loadECPublicKey() throws ParseException, IOException, JOSEException {
        String publicKeyAsString = Files.readString(Paths.get("signature-keys/JWK-EC-public-key.json"));
        JWK publicJWK = JWK.parse(publicKeyAsString);
        ECKey publicKey = publicJWK.toECKey();
        return Algorithm.ECDSA256(publicKey.toECPublicKey());
    }

    public static Algorithm loadRSAPrivateKey() throws ParseException, IOException, JOSEException {
        String privateKeyAsString = Files.readString(Paths.get("signature-keys/JWK-RSA-pair.json"));
        JWK privateJWK = JWK.parse(privateKeyAsString);
        RSAKey privateKey = privateJWK.toRSAKey();
        return Algorithm.RSA256(privateKey.toRSAPrivateKey());
    }

    public static Algorithm loadRSAPublicKey() throws ParseException, IOException, JOSEException {
        String publicKeyAsString = Files.readString(Paths.get("signature-keys/JWK-RSA-public-key.json"));
        JWK publicJWK = JWK.parse(publicKeyAsString);
        RSAKey publicKey = publicJWK.toRSAKey();
        return Algorithm.RSA256(publicKey.toRSAPublicKey());
    }
}

/*
 * Copyright 2019 IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package org.hyperledger.fabric.gateway.impl.identity;

import java.io.IOException;
import java.io.StringReader;
import java.lang.reflect.InvocationTargetException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.json.Json;
import javax.json.JsonObject;


import org.apache.milagro.amcl.FP256BN.BIG;
import org.bouncycastle.util.io.pem.PemReader;
import org.hyperledger.fabric.gateway.GatewayRuntimeException;
import org.hyperledger.fabric.gateway.IdemixIdentity;
import org.hyperledger.fabric.gateway.Identities;
import org.hyperledger.fabric.gateway.Identity;
import org.hyperledger.fabric.protos.idemix.Idemix;
import org.hyperledger.fabric.sdk.HFClient;
import org.hyperledger.fabric.sdk.User;
import org.hyperledger.fabric.sdk.exception.CryptoException;
import org.hyperledger.fabric.sdk.exception.InvalidArgumentException;
import org.hyperledger.fabric.sdk.idemix.IdemixCredential;
import org.hyperledger.fabric.sdk.idemix.IdemixIssuerPublicKey;
import org.hyperledger.fabric.sdk.identity.IdemixEnrollment;
import org.hyperledger.fabric.sdk.security.CryptoSuite;
import org.hyperledger.fabric.sdk.security.CryptoSuiteFactory;


import static java.nio.charset.StandardCharsets.UTF_8;


public enum IdemixIdentityProvider implements IdentityProvider<IdemixIdentity> {
    INSTANCE;

    private static final String TYPE_ID = "idemix";

    @Override
    public Class<IdemixIdentity> getType() {
        return IdemixIdentity.class;
    }

    @Override
    public String getTypeId() {
        return TYPE_ID;
    }

    @Override
    public JsonObject toJson(final Identity identity) {

        IdemixIdentity idemixIdentity = (IdemixIdentity) identity;

        String ipk = idemixIdentity.getIPKSerializedString();
        String revocationPk = idemixIdentity.getRPKSerializedString();
        String mspId = idemixIdentity.getMspId();
        String sk = idemixIdentity.getSKSerializedString();
        String credential = idemixIdentity.getCredentialSerializedString();
        String cri = idemixIdentity.getCRISerializedString();
        String ou = idemixIdentity.getOUString();
        String rolemask = idemixIdentity.getRoleString();

        return Json.createObjectBuilder()
                .add(IdentityConstants.JSON_VERSION, 1)
                .add(IdentityConstants.JSON_MSP_ID, mspId)
                .add(IdentityConstants.JSON_TYPE, TYPE_ID)
                .add("idemixcredentials", Json.createObjectBuilder()
                        .add("ipk", ipk)
                        .add("revocationPk", revocationPk)
                        .add("sk", sk)
                        .add("credential", credential)
                        .add("cri", cri)
                        .add("ou", ou)
                        .add("rolemask", rolemask))
                .build();

    }

    @Override
    public IdemixIdentity fromJson(final JsonObject identityData)
            throws CertificateException, InvalidKeyException, IOException {


                try {
                    return deserializeIdentity(identityData);
                } catch (RuntimeException e) {
                    throw new IOException(e);
                }
    }


    private IdemixIdentity  deserializeIdentity(final JsonObject identityData) throws IOException, CertificateException, InvalidKeyException {
        final String type = identityData.getString(IdentityConstants.JSON_TYPE);
        if (!TYPE_ID.equals(type)) {
            throw new IOException("Bad type for provider: " + type);
        }

        final int version = identityData.getInt(IdentityConstants.JSON_VERSION);
        switch (version) {
            case 1:
                return newIdentity(identityData);
            default:
                throw new IOException("Unsupported identity data version: " + version);
        }
    }


    private IdemixIdentity newIdentity(final JsonObject identityData) throws CertificateException, InvalidKeyException {
        String mspId = identityData.getString(IdentityConstants.JSON_MSP_ID);

        JsonObject idemixcredentials = identityData.getJsonObject("idemixcredentials");
        String ipk = idemixcredentials.getString("ipk");
        String revocationPk = idemixcredentials.getString("revocationPk");
        String sk = idemixcredentials.getString("sk");
        String credential = idemixcredentials.getString("credential");
        String cri = idemixcredentials.getString("cri");
        String ou = idemixcredentials.getString("ou");
        String rolemask = idemixcredentials.getString("rolemask");

        return Identities.newIdemixIdentity(ipk, revocationPk, mspId, sk, credential, cri, ou, rolemask);
    }




    @Override
    public void setUserContext(final HFClient client, final Identity identity, final String name) {

        IdemixIdentity idemixIdentity = (IdemixIdentity) identity;
        String mspId;
        IdemixEnrollment enrollment;

        try {
            byte[] ipkBytes = base64Decode(idemixIdentity.getIPKSerializedString().getBytes());
            Idemix.IssuerPublicKey ipkProto = Idemix.IssuerPublicKey.parseFrom(ipkBytes);
            IdemixIssuerPublicKey ipk = new IdemixIssuerPublicKey(ipkProto);

            String pem = new String(Base64.getDecoder().decode(idemixIdentity.getRPKSerializedString()));
            byte[] der = convertPemToDer(pem);
            PublicKey revocationPk =  KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(der));

            mspId = idemixIdentity.getMspId();

            byte[] skBytes = base64Decode(idemixIdentity.getSKSerializedString().getBytes());
            BIG sk = BIG.fromBytes(skBytes);

            byte[] credBytes = base64Decode(idemixIdentity.getCredentialSerializedString().getBytes(UTF_8));
            Idemix.Credential credProto = Idemix.Credential.parseFrom(credBytes);
            IdemixCredential cred = new IdemixCredential(credProto);

            byte[] criBytes = base64Decode(idemixIdentity.getCRISerializedString().getBytes(UTF_8));
            Idemix.CredentialRevocationInformation cri = Idemix.CredentialRevocationInformation.parseFrom(criBytes);

            String ou = idemixIdentity.getOUString();

            int roleMask = Integer.parseInt(idemixIdentity.getRoleString());

           enrollment = new IdemixEnrollment(ipk, revocationPk, mspId, sk, cred, cri, ou, roleMask);

        } catch (InvalidKeySpecException | NoSuchAlgorithmException | IOException e) {
            throw new GatewayRuntimeException("An Exception Occured at Setting User Context with Class:" + e.getClass().getName() + "exeption message: " + e);
        }

        User user = new GatewayUser(name, mspId, enrollment);

        try {
            CryptoSuite cryptoSuite = CryptoSuiteFactory.getDefault().getCryptoSuite();
            client.setCryptoSuite(cryptoSuite);
            client.setUserContext(user);
        } catch (ClassNotFoundException | CryptoException | IllegalAccessException | NoSuchMethodException
                | InstantiationException | InvalidArgumentException | InvocationTargetException e) {
            throw new GatewayRuntimeException("Failed to configure user context", e);
        }
    }

    private byte[] base64Decode(final byte[] base64EncodedByteArray) {
        return Base64.getDecoder().decode(base64EncodedByteArray);
    }


    private byte[] convertPemToDer(final String pem) throws IOException {
        PemReader pemReader = new PemReader(new StringReader(pem));
        return pemReader.readPemObject().getContent();
    }
}

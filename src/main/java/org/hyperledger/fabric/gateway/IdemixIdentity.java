/*
 * Copyright 2019 IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package org.hyperledger.fabric.gateway;

public interface IdemixIdentity extends Identity {

    /**
     * Get the Serialized (Base64 Encoded Proto Bytes) Idemix Issuer Public Key.
     * @return A Serialized Issuer Public Key String
     */
    String getIPKSerializedString();

    /**
     * Get the Serialized (Base64 Encoded PEM String) Revocation Public Key.
     * @return A Serialized Revocation Public Key String
     */
    String getRPKSerializedString();

    /**
     * Get the Serialized (Base64 Encoded Proto Bytes) Secret Key.
     * @return A Serialized Secret Key String
     */
    String getSKSerializedString();

    /**
     * Get the Serialized (Base64 Encoded Proto Bytes) Idemix Credential.
     * @return A Serialized Idemix Credential Key String
     */
    String getCredentialSerializedString();

    /**
     * Get the Serialized (Base64 Encoded Proto Bytes) Certificate Revocation Information.
     * @return A Serialized Certificate Revocation Information String
     */
    String getCRISerializedString();

    /**
     * Get the OU String.
     * @return A OU String
     */
    String getOUString();

    /**
     * Get the RoleMask string.
     * @return A RoleMask String
     */
    String getRoleString();

}

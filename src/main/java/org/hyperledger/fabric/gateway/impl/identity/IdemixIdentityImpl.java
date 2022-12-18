/*
 * Copyright 2019 IBM All Rights Reserved.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

package org.hyperledger.fabric.gateway.impl.identity;

import org.hyperledger.fabric.gateway.IdemixIdentity;

public final class IdemixIdentityImpl implements IdemixIdentity {

    private final String ipkSerializedString;
    private final String revocationPkSerializedString;
    private final String mspId;
    private final String skSerializedString;
    private final String credentialSerializedString;
    private final String criSerializedString;
    private final String ouString;
    private final String roleMaskString;


    public IdemixIdentityImpl(final String ipkSerializedString, final String revocationPkSerializedString, final String mspId,
            final String skSerializedString, final String credentialSerializedString, final String criSerializedString, final String ouString,
            final String roleMaskString) {
        this.ipkSerializedString = ipkSerializedString;
        this.revocationPkSerializedString = revocationPkSerializedString;
        this.mspId = mspId;
        this.skSerializedString = skSerializedString;
        this.credentialSerializedString = credentialSerializedString;
        this.criSerializedString = criSerializedString;
        this.ouString = ouString;
        this.roleMaskString = roleMaskString;
    }

    @Override
    public String getMspId() {
        return mspId;
    }

    @Override
    public String getIPKSerializedString() {
        return ipkSerializedString;
    }

    @Override
    public String getRPKSerializedString() {
        return revocationPkSerializedString;
    }

    @Override
    public String getSKSerializedString() {
        return skSerializedString;
    }

    @Override
    public String getCredentialSerializedString() {
        return credentialSerializedString;
    }

    @Override
    public String getCRISerializedString() {
        return criSerializedString;
    }

    @Override
    public String getOUString() {
        return ouString;
    }

    @Override
    public String getRoleString() {
        return roleMaskString;
    }
}

/*
 * Copyright 2015 floragunn UG (haftungsbeschränkt)
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * 
 */

package com.floragunn.searchguard.ssl;

import java.util.Objects;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLParameters;

import org.elasticsearch.ElasticsearchException;
import org.elasticsearch.common.settings.Settings;

import com.floragunn.searchguard.ssl.util.SSLConfigConstants;

public class ExternalSearchGuardKeyStore implements SearchGuardKeyStore {

    private static final String EXTERNAL = "EXTERNAL";
    private static SSLContext sslContext;
    private final Settings settings;

    public ExternalSearchGuardKeyStore(final Settings settings) {
        this.settings = Objects.requireNonNull(settings);
        
        if(!ExternalSearchGuardKeyStore.hasSslContext()) {
            throw new ElasticsearchException("no external ssl context was set");
        }
    }

    @Override
    public SSLEngine createHTTPSSLEngine() throws SSLException {
        throw new SSLException("not implemented");
    }

    @Override
    public SSLEngine createServerTransportSSLEngine() throws SSLException {
        throw new SSLException("not implemented");
    }

    @Override
    public SSLEngine createClientTransportSSLEngine(final String peerHost, final int peerPort) throws SSLException {
        if (peerHost != null) {
            final SSLEngine engine = sslContext.createSSLEngine(peerHost, peerPort);
            
            final SSLParameters sslParams = new SSLParameters();
            sslParams.setEndpointIdentificationAlgorithm("HTTPS");
            engine.setSSLParameters(sslParams);
            engine.setEnabledProtocols(SSLConfigConstants.getSecureSSLProtocols(settings, false));
            engine.setUseClientMode(true);
            return engine;
        } else {
            final SSLEngine engine = sslContext.createSSLEngine();
            engine.setEnabledProtocols(SSLConfigConstants.getSecureSSLProtocols(settings, false));
            engine.setUseClientMode(true);
            return engine;
        }
    }

    @Override
    public String getHTTPProviderName() {
        return null;
    }

    @Override
    public String getTransportServerProviderName() {
        return null;
    }

    @Override
    public String getTransportClientProviderName() {
        return EXTERNAL;
    }

    public static void setSslContext(final SSLContext sslContext) {
        ExternalSearchGuardKeyStore.sslContext = Objects.requireNonNull(sslContext);
    }
    
    public static boolean unsetSslContext() {
        return ExternalSearchGuardKeyStore.sslContext == null;
    }
    
    public static boolean hasSslContext() {
        return ExternalSearchGuardKeyStore.sslContext != null;
    }
}

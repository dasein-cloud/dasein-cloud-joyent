/**
 * Copyright (C) 2009-2015 Dell, Inc
 * See annotations for authorship information
 *
 * ====================================================================
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * ====================================================================
 */

package org.dasein.security.joyent;

import org.apache.http.*;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.GzipDecompressingEntity;
import org.apache.http.conn.params.ConnRoutePNames;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.params.BasicHttpParams;
import org.apache.http.params.HttpParams;
import org.apache.http.params.HttpProtocolParams;
import org.apache.http.protocol.HttpContext;
import org.dasein.cloud.CloudException;
import org.dasein.cloud.InternalException;
import org.dasein.cloud.ProviderContext;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.util.Properties;

public class DefaultClientFactory implements JoyentClientFactory {

    private final ProviderContext providerContext;

    public DefaultClientFactory( ProviderContext providerContext ) {
        this.providerContext = providerContext;
    }

    @Override
    public @Nonnull HttpClient getClient(String endpoint) throws CloudException, InternalException {
        if( providerContext == null ) {
            throw new InternalException("No context was defined for this request");
        }

        final HttpParams params = new BasicHttpParams();

        HttpProtocolParams.setVersion(params, HttpVersion.HTTP_1_1);
        HttpProtocolParams.setContentCharset(params, Consts.UTF_8.toString());
        HttpProtocolParams.setUserAgent(params, "Dasein Cloud");

        Properties p = providerContext.getCustomProperties();
        if( p != null ) {
            String proxyHost = p.getProperty("proxyHost");
            String proxyPortStr = p.getProperty("proxyPort");
            int proxyPort = 0;
            if( proxyPortStr != null ) {
                proxyPort = Integer.parseInt(proxyPortStr);
            }
            if( proxyHost != null && proxyHost.length() > 0 && proxyPort > 0 ) {
                params.setParameter(ConnRoutePNames.DEFAULT_PROXY,
                        new HttpHost(proxyHost, proxyPort)
                );
            }
        }
        DefaultHttpClient client = new DefaultHttpClient(params);
        // Joyent does not support gzip at the moment (7.2), but in case it will
        // in the future we might just leave these here
        client.addRequestInterceptor(new HttpRequestInterceptor() {
            public void process(
                    final HttpRequest request,
                    final HttpContext context) throws HttpException, IOException {
                if( !request.containsHeader("Accept-Encoding") ) {
                    request.addHeader("Accept-Encoding", "gzip");
                }
                request.setParams(params);
            }
        });
        client.addResponseInterceptor(new HttpResponseInterceptor() {
            public void process(
                    final HttpResponse response,
                    final HttpContext context) throws HttpException, IOException {
                HttpEntity entity = response.getEntity();
                if( entity != null ) {
                    Header header = entity.getContentEncoding();
                    if( header != null ) {
                        for( HeaderElement codec : header.getElements() ) {
                            if( codec.getName().equalsIgnoreCase("gzip") ) {
                                response.setEntity(
                                        new GzipDecompressingEntity(response.getEntity()));
                                break;
                            }
                        }
                    }
                }
            }
        });
        return client;
    }

    protected ProviderContext getProviderContext() {
        return providerContext;
    }
}

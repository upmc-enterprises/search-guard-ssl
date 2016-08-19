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

import io.netty.handler.ssl.OpenSsl;

import java.io.ByteArrayInputStream;
import java.net.InetSocketAddress;
import java.util.HashSet;
import java.util.Set;

import org.elasticsearch.action.admin.cluster.health.ClusterHealthRequest;
import org.elasticsearch.action.admin.cluster.node.hotthreads.NodesHotThreadsRequest;
import org.elasticsearch.action.admin.cluster.node.info.NodesInfoRequest;
import org.elasticsearch.action.admin.cluster.node.stats.NodesStatsRequest;
import org.elasticsearch.action.admin.cluster.state.ClusterStateRequest;
import org.elasticsearch.action.admin.cluster.stats.ClusterStatsRequest;
import org.elasticsearch.action.admin.cluster.tasks.PendingClusterTasksRequest;
import org.elasticsearch.action.index.IndexRequest;
import org.elasticsearch.client.transport.TransportClient;
import org.elasticsearch.common.io.stream.BytesStreamOutput;
import org.elasticsearch.common.io.stream.InputStreamStreamInput;
import org.elasticsearch.common.io.stream.StreamInput;
import org.elasticsearch.common.io.stream.StreamOutput;
import org.elasticsearch.common.settings.Settings;
import org.elasticsearch.common.transport.InetSocketTransportAddress;
import org.elasticsearch.common.xcontent.ToXContent;
import org.elasticsearch.common.xcontent.XContentBuilder;
import org.elasticsearch.common.xcontent.json.JsonXContent;
import org.elasticsearch.monitor.jvm.JvmInfo;
import org.junit.Assert;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;

import com.floragunn.searchguard.ssl.util.SSLConfigConstants;

public class OpenSSLTest extends SSLTest {

    @Before
    public void setup() {
        allowOpenSSL = true;
    }

    
    @Test
    public void testEnsureOpenSSLAvailability() {
        Assert.assertTrue("OpenSSL not available: "+String.valueOf(OpenSsl.unavailabilityCause()), OpenSsl.isAvailable());
                
        /*String allowOpenSSLProperty = System.getenv("SG_ALLOW_OPENSSL");
        System.out.println("SG_ALLOW_OPENSSL "+allowOpenSSLProperty);
        if(Boolean.parseBoolean(allowOpenSSLProperty)) {
            System.out.println("OpenSSL must be available");
            Assert.assertTrue(String.valueOf(OpenSsl.unavailabilityCause()), OpenSsl.isAvailable());
        } else {
            System.out.println("OpenSSL can be available");
        }*/
    }

    /*
    @Override
    @Test
    public void testHttps() throws Exception {
        Assume.assumeTrue(OpenSsl.isAvailable());
        super.testHttps();
    }

    @Override
    @Test
    public void testHttpsAndNodeSSL() throws Exception {
        Assume.assumeTrue(OpenSsl.isAvailable());
        super.testHttpsAndNodeSSL();
    }

    @Override
    @Test
    public void testHttpPlainFail() throws Exception {
        Assume.assumeTrue(OpenSsl.isAvailable());
        super.testHttpPlainFail();
    }

    @Override
    @Test
    public void testHttpsNoEnforce() throws Exception {
        Assume.assumeTrue(OpenSsl.isAvailable());
        super.testHttpsNoEnforce();
    }

    @Override
    @Test
    public void testHttpsV3Fail() throws Exception {
        Assume.assumeTrue(OpenSsl.isAvailable());
        super.testHttpsV3Fail();
    }

    @Override
    @Test(timeout=40000)
    public void testTransportClientSSL() throws Exception {
        Assume.assumeTrue(OpenSsl.isAvailable());
        super.testTransportClientSSL();
    }

    @Override
    @Test(timeout=40000)
    public void testNodeClientSSL() throws Exception {
        Assume.assumeTrue(OpenSsl.isAvailable());
        super.testNodeClientSSL();
    }

    @Override
    @Test(timeout=40000)
    public void testTransportClientSSLFail() throws Exception {
        Assume.assumeTrue(OpenSsl.isAvailable());
        super.testTransportClientSSLFail();
    }
    
    @Override
    @Test
    public void testHttpsOptionalAuth() throws Exception {
        Assume.assumeTrue(OpenSsl.isAvailable());
        super.testHttpsOptionalAuth();
    }
    
    @Test
    public void testAvailCiphersOpenSSL() throws Exception {
        Assume.assumeTrue(OpenSsl.isAvailable());

        // Set<String> openSSLAvailCiphers = new
        // HashSet<>(OpenSsl.availableCipherSuites());
        // System.out.println("OpenSSL available ciphers: "+openSSLAvailCiphers);
        // ECDHE-RSA-AES256-SHA, ECDH-ECDSA-AES256-SHA, DH-DSS-DES-CBC-SHA,
        // ADH-AES256-SHA256, ADH-CAMELLIA128-SHA

        final Set<String> openSSLSecureCiphers = new HashSet<>();
        for (final String secure : SSLConfigConstants.getSecureSSLCiphers(Settings.EMPTY, false)) {
            if (OpenSsl.isCipherSuiteAvailable(secure)) {
                openSSLSecureCiphers.add(secure);
            }
        }

        System.out.println("OpenSSL secure ciphers: " + openSSLSecureCiphers);
        Assert.assertTrue(openSSLSecureCiphers.size() > 0);
    }
    
    @Override
    @Test
    public void testHttpsEnforceFail() throws Exception {
        Assume.assumeTrue(OpenSsl.isAvailable());
        super.testHttpsEnforceFail();
    }

    @Override
    @Test
    public void testCipherAndProtocols() throws Exception {
        Assume.assumeTrue(OpenSsl.isAvailable());
        super.testCipherAndProtocols();
    }

    @Override
    @Test
    public void testHttpsAndNodeSSLFailedCipher() throws Exception {
        Assume.assumeTrue(OpenSsl.isAvailable());
        super.testHttpsAndNodeSSLFailedCipher();
    }*/
    
    @Override
    @Test(timeout=50000)
    public void testTransportClientNodesInfo() throws Exception {
        Assume.assumeTrue(OpenSsl.isAvailable());
        super.testTransportClientNodesInfo();
    }
    @Test(timeout=50000)
    public void test0() throws Exception {

        final Settings settings = Settings.settingsBuilder().put("searchguard.ssl.transport.enabled", true)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS, "node-0")
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.transport.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks"))
                .put("searchguard.ssl.transport.enforce_hostname_verification", false)
                .put("searchguard.ssl.transport.resolve_hostname", false).build();

        startES(settings);
        
        log.debug("Elasticsearch started");

        final Settings tcSettings = Settings.builder().put("cluster.name", clustername).put("path.home", ".").put(settings).build();

        try (TransportClient tc = TransportClient.builder().settings(tcSettings).addPlugin(SearchGuardSSLPlugin.class).build()) {
            
            log.debug("TransportClient built, connect now to {}:{}", nodeHost, nodePort);
            
            tc.addTransportAddress(new InetSocketTransportAddress(new InetSocketAddress(nodeHost, nodePort)));
            
            log.debug("TransportClient connected");
            Assert.assertEquals("test", tc.index(new IndexRequest("test","test").refresh(true).source("{\"a\":5}")).actionGet().getIndex());           
            Assert.assertEquals(3, tc.admin().cluster().health(new ClusterHealthRequest("test")).actionGet().getNumberOfNodes());
            log.debug("ClusterHealth done");            
            
            try {
                tc.admin().cluster().nodesInfo(new NodesInfoRequest().clear()).actionGet(10000).getNodes();
            } catch (Exception e) {
                System.out.println("fail none::"+e);
            }   
            
            try {
                tc.admin().cluster().nodesInfo(new NodesInfoRequest().clear().settings(true)).actionGet(10000).getNodes();
            } catch (Exception e) {
                System.out.println("fail se::"+e);
            }  
            
            try {
                tc.admin().cluster().nodesInfo(new NodesInfoRequest().clear().http(true)).actionGet(10000).getNodes();
            } catch (Exception e) {
                System.out.println("fail ht::"+e);
            }  
            
            try {
                tc.admin().cluster().nodesInfo(new NodesInfoRequest().clear().plugins(true)).actionGet(10000).getNodes();
            } catch (Exception e) {
                System.out.println("fail pl::"+e);
            }  
            
            try {
                tc.admin().cluster().nodesInfo(new NodesInfoRequest().clear().jvm(true)).actionGet(10000).getNodes();
            } catch (Exception e) {
                System.out.println("fail jvm::"+e);
            }  
            
            
            try {
                tc.admin().cluster().nodesInfo(new NodesInfoRequest().clear().os(true)).actionGet(10000).getNodes();
            } catch (Exception e) {
                System.out.println("fail os::"+e);
            }  
            
            
            try {
                tc.admin().cluster().nodesInfo(new NodesInfoRequest().clear().process(true)).actionGet(10000).getNodes();
            } catch (Exception e) {
                System.out.println("fail pro::"+e);
            } 
            
            
            try {
                tc.admin().cluster().nodesInfo(new NodesInfoRequest().clear().threadPool(true)).actionGet(10000).getNodes();
            } catch (Exception e) {
                System.out.println("fail tp::"+e);
            } 
            
            
            try {
                tc.admin().cluster().nodesInfo(new NodesInfoRequest().clear().transport(true)).actionGet(10000).getNodes();
            } catch (Exception e) {
                System.out.println("fail tr::"+e);
            } 
            
            
            

        }
    }
    
    @Test(timeout=50000)
    public void test1() throws Exception {

        final Settings settings = Settings.settingsBuilder().put("searchguard.ssl.transport.enabled", true)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS, "node-0")
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.transport.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks"))
                .put("searchguard.ssl.transport.enforce_hostname_verification", false)
                .put("searchguard.ssl.transport.resolve_hostname", false).build();

        startES(settings);
        
        log.debug("Elasticsearch started");

        final Settings tcSettings = Settings.builder().put("cluster.name", clustername).put("path.home", ".").put(settings).build();

        try (TransportClient tc = TransportClient.builder().settings(tcSettings).addPlugin(SearchGuardSSLPlugin.class).build()) {
            
            log.debug("TransportClient built, connect now to {}:{}", nodeHost, nodePort);
            
            tc.addTransportAddress(new InetSocketTransportAddress(new InetSocketAddress(nodeHost, nodePort)));
            
            log.debug("TransportClient connected");
            Assert.assertEquals("test", tc.index(new IndexRequest("test","test").refresh(true).source("{\"a\":5}")).actionGet().getIndex());           
            Assert.assertEquals(3, tc.admin().cluster().health(new ClusterHealthRequest("test")).actionGet().getNumberOfNodes());
            log.debug("ClusterHealth done");            
            Assert.assertEquals(3, tc.admin().cluster().nodesHotThreads(new NodesHotThreadsRequest()).actionGet(10000).getNodes().length);            
            log.debug("NodesHotThreadsRequest asserted");
            Assert.assertEquals(3, tc.admin().cluster().nodesStats(new NodesStatsRequest()).actionGet(10000).getNodes().length);            
            log.debug("NodesStatsRequest asserted");
            Assert.assertNotNull(tc.admin().cluster().clusterStats(new ClusterStatsRequest()).actionGet(10000));            
            log.debug("ClusterStatsRequest asserted");
            Assert.assertNotNull(tc.admin().cluster().pendingClusterTasks(new PendingClusterTasksRequest()).actionGet(10000));  
            log.debug("PendingClusterTasksRequest asserted");
            Assert.assertNotNull(tc.admin().cluster().state(new ClusterStateRequest()).actionGet(10000).getState());   
            log.debug("ClusterStateRequest asserted");
        }
    }
    
    @Test(timeout=50000)
    public void test2() throws Exception {

        final Settings settings = Settings.settingsBuilder().put("searchguard.ssl.transport.enabled", true)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS, "node-0")
                .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                .put("searchguard.ssl.transport.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks"))
                .put("searchguard.ssl.transport.enforce_hostname_verification", false)
                .put("searchguard.ssl.transport.resolve_hostname", false).build();

        startES(settings);
        
        log.debug("Elasticsearch started");

        final Settings tcSettings = Settings.builder().put("cluster.name", clustername).put("path.home", ".").put(settings).build();

        try (TransportClient tc = TransportClient.builder().settings(tcSettings).addPlugin(SearchGuardSSLPlugin.class).build()) {
            
            log.debug("TransportClient built, connect now to {}:{}", nodeHost, nodePort);
            
            tc.addTransportAddress(new InetSocketTransportAddress(new InetSocketAddress(nodeHost, nodePort)));
            
            log.debug("TransportClient connected");
            Assert.assertEquals("test", tc.index(new IndexRequest("test","test").refresh(true).source("{\"a\":5}")).actionGet().getIndex());           
            Assert.assertEquals(3, tc.admin().cluster().health(new ClusterHealthRequest("test")).actionGet().getNumberOfNodes());
            log.debug("ClusterHealth done");            
             Assert.assertEquals(3, tc.admin().cluster().nodesStats(new NodesStatsRequest()).actionGet(10000).getNodes().length);            
            log.debug("NodesStatsRequest asserted");
            Assert.assertNotNull(tc.admin().cluster().clusterStats(new ClusterStatsRequest()).actionGet(10000));            
            log.debug("ClusterStatsRequest asserted");
            Assert.assertNotNull(tc.admin().cluster().pendingClusterTasks(new PendingClusterTasksRequest()).actionGet(10000));  
            log.debug("PendingClusterTasksRequest asserted");
            Assert.assertNotNull(tc.admin().cluster().state(new ClusterStateRequest()).actionGet(10000).getState());   
            log.debug("ClusterStateRequest asserted");
        }
    }
        
        @Test(timeout=50000)
        public void test3() throws Exception {

            final Settings settings = Settings.settingsBuilder().put("searchguard.ssl.transport.enabled", true)
                    .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                    .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                    .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS, "node-0")
                    .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                    .put("searchguard.ssl.transport.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks"))
                    .put("searchguard.ssl.transport.enforce_hostname_verification", false)
                    .put("searchguard.ssl.transport.resolve_hostname", false).build();

            startES(settings);
            
            log.debug("Elasticsearch started");

            final Settings tcSettings = Settings.builder().put("cluster.name", clustername).put("path.home", ".").put(settings).build();

            try (TransportClient tc = TransportClient.builder().settings(tcSettings).addPlugin(SearchGuardSSLPlugin.class).build()) {
                
                log.debug("TransportClient built, connect now to {}:{}", nodeHost, nodePort);
                
                tc.addTransportAddress(new InetSocketTransportAddress(new InetSocketAddress(nodeHost, nodePort)));
                
                log.debug("TransportClient connected");
                Assert.assertEquals("test", tc.index(new IndexRequest("test","test").refresh(true).source("{\"a\":5}")).actionGet().getIndex());           
                Assert.assertEquals(3, tc.admin().cluster().health(new ClusterHealthRequest("test")).actionGet().getNumberOfNodes());
                log.debug("ClusterHealth done");            
                          Assert.assertNotNull(tc.admin().cluster().clusterStats(new ClusterStatsRequest()).actionGet(10000));            
                log.debug("ClusterStatsRequest asserted");
                Assert.assertNotNull(tc.admin().cluster().pendingClusterTasks(new PendingClusterTasksRequest()).actionGet(10000));  
                log.debug("PendingClusterTasksRequest asserted");
                Assert.assertNotNull(tc.admin().cluster().state(new ClusterStateRequest()).actionGet(10000).getState());   
                log.debug("ClusterStateRequest asserted");
            }
        }
    
    
        
        @Test(timeout=50000)
        public void test4() throws Exception {

            final Settings settings = Settings.settingsBuilder().put("searchguard.ssl.transport.enabled", true)
                    .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                    .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                    .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS, "node-0")
                    .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                    .put("searchguard.ssl.transport.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks"))
                    .put("searchguard.ssl.transport.enforce_hostname_verification", false)
                    .put("searchguard.ssl.transport.resolve_hostname", false).build();

            startES(settings);
            
            log.debug("Elasticsearch started");

            final Settings tcSettings = Settings.builder().put("cluster.name", clustername).put("path.home", ".").put(settings).build();

            try (TransportClient tc = TransportClient.builder().settings(tcSettings).addPlugin(SearchGuardSSLPlugin.class).build()) {
                
                log.debug("TransportClient built, connect now to {}:{}", nodeHost, nodePort);
                
                tc.addTransportAddress(new InetSocketTransportAddress(new InetSocketAddress(nodeHost, nodePort)));
                
                log.debug("TransportClient connected");
                Assert.assertEquals("test", tc.index(new IndexRequest("test","test").refresh(true).source("{\"a\":5}")).actionGet().getIndex());           
                Assert.assertEquals(3, tc.admin().cluster().health(new ClusterHealthRequest("test")).actionGet().getNumberOfNodes());
                log.debug("ClusterHealth done");            
                          Assert.assertNotNull(tc.admin().cluster().clusterStats(new ClusterStatsRequest()).actionGet(10000));            
                  log.debug("PendingClusterTasksRequest asserted");
                Assert.assertNotNull(tc.admin().cluster().state(new ClusterStateRequest()).actionGet(10000).getState());   
                log.debug("ClusterStateRequest asserted");
            }
        }
    
        @Test(timeout=50000)
        public void test5() throws Exception {

            final Settings settings = Settings.settingsBuilder().put("searchguard.ssl.transport.enabled", true)
                    .put(SSLConfigConstants.SEARCHGUARD_SSL_HTTP_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                    .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_ENABLE_OPENSSL_IF_AVAILABLE, allowOpenSSL)
                    .put(SSLConfigConstants.SEARCHGUARD_SSL_TRANSPORT_KEYSTORE_ALIAS, "node-0")
                    .put("searchguard.ssl.transport.keystore_filepath", getAbsoluteFilePathFromClassPath("node-0-keystore.jks"))
                    .put("searchguard.ssl.transport.truststore_filepath", getAbsoluteFilePathFromClassPath("truststore.jks"))
                    .put("searchguard.ssl.transport.enforce_hostname_verification", false)
                    .put("searchguard.ssl.transport.resolve_hostname", false).build();

            startES(settings);
            
            log.debug("Elasticsearch started");

            final Settings tcSettings = Settings.builder().put("cluster.name", clustername).put("path.home", ".").put(settings).build();

            try (TransportClient tc = TransportClient.builder().settings(tcSettings).addPlugin(SearchGuardSSLPlugin.class).build()) {
                
                log.debug("TransportClient built, connect now to {}:{}", nodeHost, nodePort);
                
                tc.addTransportAddress(new InetSocketTransportAddress(new InetSocketAddress(nodeHost, nodePort)));
                
                log.debug("TransportClient connected");
                Assert.assertEquals("test", tc.index(new IndexRequest("test","test").refresh(true).source("{\"a\":5}")).actionGet().getIndex());           
                Assert.assertEquals(3, tc.admin().cluster().health(new ClusterHealthRequest("test")).actionGet().getNumberOfNodes());
                log.debug("ClusterHealth done");            
                                  Assert.assertNotNull(tc.admin().cluster().state(new ClusterStateRequest()).actionGet(10000).getState());   
                log.debug("ClusterStateRequest asserted");
            }
        }
 
        
        
        @Test(timeout=50000)
        public void testjvminfo() throws Exception {
            JvmInfo.jvmInfo().getBootClassPath();
            JvmInfo.jvmInfo().getClassPath();
            JvmInfo.jvmInfo().getInputArguments();
            JvmInfo.jvmInfo().getMem();
            JvmInfo.jvmInfo().getPid();
            JvmInfo.jvmInfo().getStartTime();
            JvmInfo.jvmInfo().getSystemProperties();
            JvmInfo.jvmInfo().getVersion();
            JvmInfo.jvmInfo().getVmName();
            JvmInfo.jvmInfo().getVmVendor();
            JvmInfo.jvmInfo().getVmVersion();
            BytesStreamOutput so = new BytesStreamOutput();
            JvmInfo.jvmInfo().writeTo(so);
            JvmInfo j = JvmInfo.readJvmInfo(new InputStreamStreamInput(new ByteArrayInputStream(so.bytes().toBytes())));
            System.out.println(j.getClassPath());
            
            
           System.out.println(JvmInfo.jvmInfo().toXContent(JsonXContent.contentBuilder(), ToXContent.EMPTY_PARAMS).string());
            
            
        }
        
        
        
        
        
}

/*
 * Copyright (C) 2013 tarent AG
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

package org.osiam.client;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;

import org.apache.http.Header;
import org.apache.http.HeaderElement;
import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.params.ClientPNames;
import org.apache.http.client.params.CookiePolicy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.message.BasicNameValuePair;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.osiam.client.oauth.AccessToken;
import org.osiam.client.oauth.Scope;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.TestExecutionListeners;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.support.DependencyInjectionTestExecutionListener;

import com.github.springtestdbunit.DbUnitTestExecutionListener;
import com.github.springtestdbunit.annotation.DatabaseOperation;
import com.github.springtestdbunit.annotation.DatabaseSetup;
import com.github.springtestdbunit.annotation.DatabaseTearDown;

@RunWith(SpringJUnit4ClassRunner.class)
@ContextConfiguration("/context.xml")
@TestExecutionListeners({ DependencyInjectionTestExecutionListener.class,
        DbUnitTestExecutionListener.class })
@DatabaseTearDown(value = "/database_tear_down.xml", type = DatabaseOperation.DELETE_ALL)
public class ChangedPasswordEncoderIT extends AbstractIntegrationTestBase {

    private URI loginUri = OSIAM_CONNECTOR.getAuthorizationUri(Scope.ADMIN);
    private CloseableHttpClient httpClient = HttpClientBuilder.create().build();
    private String authCode;
    private AccessToken accessToken;
    private HttpResponse authCodeResponse;

    @Before
    public void before() {
        loginUri = OSIAM_CONNECTOR.getAuthorizationUri(Scope.ADMIN);
    }

    @Test
    @DatabaseSetup("/database_seed.xml")
    public void test_successful_login() throws IOException {
        givenValidAuthCode("marissa", "koala", "internal");
        givenAuthCode();
        givenAccessTokenUsingAuthCode();
        assertTrue(accessToken != null);
        assertNotNull(accessToken.getRefreshToken());
    }

    private void givenAccessTokenUsingAuthCode() {
        accessToken = OSIAM_CONNECTOR.retrieveAccessToken(authCode);
    }

    private String givenValidAuthCode(String username, String password, String provider) throws IOException {
        String currentRedirectUri;

        {
            HttpGet httpGet = new HttpGet(loginUri);
            httpClient.execute(httpGet);
            httpGet.releaseConnection();
        }

        {
            HttpPost httpPost = new HttpPost(AUTH_ENDPOINT_ADDRESS + "/login/check");

            List<NameValuePair> loginCredentials = new ArrayList<>();
            loginCredentials
                    .add(new BasicNameValuePair("username", username));
            loginCredentials.add(new BasicNameValuePair("password", password));
            loginCredentials.add(new BasicNameValuePair("provider", provider));
            UrlEncodedFormEntity loginCredentialsEntity = new UrlEncodedFormEntity(
                    loginCredentials, "UTF-8");

            httpPost.setEntity(loginCredentialsEntity);
            HttpResponse response = httpClient.execute(httpPost);

            currentRedirectUri = response.getLastHeader("Location").getValue();

            httpPost.releaseConnection();
        }

        {
            HttpGet httpGet = new HttpGet(currentRedirectUri);
            httpGet.getParams().setParameter(ClientPNames.COOKIE_POLICY,
                    CookiePolicy.NETSCAPE);
            httpGet.getParams().setBooleanParameter("http.protocol.handle-redirects", false);
            httpClient.execute(httpGet);
            httpGet.releaseConnection();
        }

        {
            HttpPost httpPost = new HttpPost(
                    AUTH_ENDPOINT_ADDRESS + "/oauth/authorize");

            List<NameValuePair> loginCredentials = new ArrayList<>();
            loginCredentials.add(new BasicNameValuePair("user_oauth_approval", "true"));
            UrlEncodedFormEntity loginCredentialsEntity = new UrlEncodedFormEntity(loginCredentials, "UTF-8");

            httpPost.setEntity(loginCredentialsEntity);
            authCodeResponse = httpClient.execute(httpPost);

            httpPost.releaseConnection();
        }
        return currentRedirectUri;
    }

    private void givenAuthCode() {
        Header header = authCodeResponse.getLastHeader("Location");
        if (header == null) {
            throw new RuntimeException("The Location Header is null");
        }
        HeaderElement[] elements = header.getElements();
        for (HeaderElement actHeaderElement : elements) {
            if (actHeaderElement.getName().contains("code")) {
                authCode = actHeaderElement.getValue();
                break;
            }
            if (actHeaderElement.getName().contains("error")) {
                fail("The user had denied the access to his data.");
            }
        }
        if (authCode == null) {
            fail("Could not find any auth code or error message in the given Response");
        }
    }
}

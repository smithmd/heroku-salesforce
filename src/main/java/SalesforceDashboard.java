import java.io.*;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.MessageFormat;
import javax.servlet.ServletException;
import javax.servlet.http.*;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.*;
import org.apache.commons.codec.binary.Base64;

public class SalesforceDashboard extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {

//        String secrets = System.getenv().get("SECRET_STUFF");

        String secrets = requestAccessToken();
        resp.getWriter().print(secrets);
    }

    public static void main(String[] args) throws Exception {
        Server server = new Server(Integer.valueOf(System.getenv("PORT")));
        ServletContextHandler context = new ServletContextHandler(ServletContextHandler.SESSIONS);
        context.setContextPath("/");
        server.setHandler(context);
        context.addServlet(new ServletHolder(new SalesforceDashboard()), "/*");
        server.start();
        server.join();
    }

    public String requestAccessToken() {
        StringBuilder response = new StringBuilder();

        try {
            URL url = new URL("https://test.salesforce.com/services/oauth2/token");
            HttpURLConnection con = (HttpURLConnection) url.openConnection();
            //add request header
            con.setRequestMethod("POST");
            con.setRequestProperty("User-Agent", "Mozilla/5.0");
            con.setRequestProperty("Accept-Language", "en-US,en;q=0.5");
            con.setRequestProperty("Content-Type","application/x-www-form-urlencoded");
            con.setConnectTimeout(60*1000);

            final String grantType = URLEncoder.encode("urn:ietf:params:oauth:grant-type:jwt-bearer", "UTF-8");
            final String token = URLEncoder.encode(createToken(), "UTF-8");
            final String urlParameters = "grant_type=" + grantType + "&assertion=" + token;

            System.out.println("URL Parameters: " + urlParameters);

            con.setDoOutput(true);
            DataOutputStream wr = new DataOutputStream(con.getOutputStream());
            wr.writeBytes(urlParameters);
            wr.flush();
            wr.close();

            int responseCode = con.getResponseCode();

            System.out.println("\n Sending POST to request URL: " + url);
            System.out.println("Post parameters : " + urlParameters);
            System.out.println("Response Code : " + responseCode);
            System.out.println(con.getResponseMessage());
            System.out.println(con.toString());

            BufferedReader in = new BufferedReader(
                    new InputStreamReader(con.getInputStream())
            );

            String inputLine;

            while((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }

            in.close();

            System.out.println(response);

            return response.toString();
        } catch (MalformedURLException e) {
            return "MalformedURLException: " + e.getMessage();
        } catch (IOException e) {
            return "IOException: " + e.getMessage() + "\nResponse:\n" + response.toString();
        }

    }

    private String createToken() {

        final String header = "(\"alg\":\"RS256\"}";
        final String claimTemplate = "'{'\"iss\": \"{0}\", \"prn\": \"{1}\", \"aud\": \"{2}\", \"exp\": \"{3}\"'}'";

        try {
            final StringBuilder token = new StringBuilder();

            //Encode the JWT Header and add it to our string to sign
            token.append(Base64.encodeBase64URLSafeString(header.getBytes("UTF-8")));
            token.append('.');

            final String[] claimArray = new String[4];
            claimArray[0] = System.getenv().get("SECRET_KEY");
            claimArray[1] = System.getenv().get("USER_NAME");
            claimArray[2] = System.getenv().get("LOGIN_PATH");
            claimArray[3] = Long.toString( (System.currentTimeMillis()/1000) + 300);

            final MessageFormat claims = new MessageFormat(claimTemplate);
            final String payload = claims.format(claimArray);

            // Add the encoded claims object
            token.append(Base64.encodeBase64URLSafeString(payload.getBytes("UTF-8")));

            final String privateKeyString = System.getenv().get("PRIVATE_KEY");
//            System.out.println(privateKeyString);

            Base64 b64PK = new Base64();
            byte [] decoded = b64PK.decode(privateKeyString);

            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);

            PrivateKey pk = KeyFactory.getInstance("RSA").generatePrivate(spec);

            // should have a PrivateKey at this point, unless that was just gibberish...
            // Sign the JWT Header + "." + JWT Claims object
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initSign(pk);
            sig.update(token.toString().getBytes("UTF-8"));
            String signedPayload = Base64.encodeBase64URLSafeString(sig.sign());

            token.append(".");

            token.append(signedPayload);

            return token.toString();

        } catch (Exception e) {
            System.err.println(e.getMessage());
            return null;
        }
    }
}

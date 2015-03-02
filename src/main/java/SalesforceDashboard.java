import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import javax.servlet.ServletException;
import javax.servlet.http.*;

import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.servlet.*;
import org.apache.commons.codec.binary.Base64;

public class SalesforceDashboard extends HttpServlet {

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        resp.getWriter().print(System.getenv().get("SECRET_KEY'"));
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

        try {
            final URL url = new URL("https://test.salesforce.com/services/oauth2/token");
            final HttpURLConnection conn = (HttpURLConnection) url.openConnection();

            conn.setRequestMethod("POST");
            conn.setRequestProperty("User-Agent", "Mozilla/5.0");
            conn.setRequestProperty("Accept-Language", "en-US,en;q=0.5");
            conn.setRequestProperty("Content-Type", "application/x-www-form-urlencoded");
            conn.setConnectTimeout(60*1000);

            final String grantType = URLEncoder.encode("urn:ietf:params:oauth:grant-type:jwt-bearer", "UTF-8");
            final String token = URLEncoder.encode(createToken());


            return "";
        } catch (MalformedURLException e) {
            return "MalformedURLException: " + e.getMessage();
        } catch (IOException e) {
            return "IOException: " + e.getMessage();
        }

    }

    private String createToken() {

        String header = "(\"alg\":\"RS256\"}";
        String claimTemplate = "'{'\"iss\": \"{0}\", \"prn\": \"{1}\", \"aud\": \"{2}\", \"exp\": \"{3}\"'}'";

        try {
            StringBuffer token = new StringBuffer();

            //Encode the JWT Header and add it to our string to sign
            token.append(org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString(header.getBytes("UTF-8")));
            token.append('.');

        } catch (Exception e) {
            System.err.println(e.getMessage());
            return null;
        }

        return null;
    }
}

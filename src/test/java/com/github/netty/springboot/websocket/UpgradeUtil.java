package com.github.netty.springboot.websocket;

/**
 * Created by acer01 on 2018/10/12/012.
 */
import com.github.netty.core.constants.HttpHeaderConstants;
import com.github.netty.core.util.CaseInsensitiveKeyMap;

import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.websocket.*;
import javax.websocket.server.HandshakeRequest;
import javax.websocket.server.ServerContainer;
import javax.websocket.server.ServerEndpointConfig;
import java.io.IOException;
import java.lang.reflect.GenericArrayType;
import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.lang.reflect.TypeVariable;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.SecureRandom;
import java.util.*;
import java.util.Map.Entry;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentLinkedQueue;

public class UpgradeUtil {

    public static final String WS_VERSION = "13";

    private static final byte[] WS_ACCEPT =
            "258EAFA5-E914-47DA-95CA-C5AB0DC85B11".getBytes(
                    StandardCharsets.ISO_8859_1);

    private UpgradeUtil() {
        // Utility class. Hide default constructor.
    }

    /**
     * Checks to see if this is an HTTP request that includes a valid upgrade
     * request to web socket.
     * <p>
     * Note: RFC 2616 does not limit HTTP upgrade to GET requests but the Java
     *       WebSocket spec 1.0, section 8.2 implies such a limitation and RFC
     *       6455 section 4.1 requires that a WebSocket Upgrade uses GET.
     * @param request  The request to check if it is an HTTP upgrade request for
     *                 a WebSocket connection
     * @param response The response associated with the request
     * @return <code>true</code> if the request includes a HTTP Upgrade request
     *         for the WebSocket protocol, otherwise <code>false</code>
     */
    public static boolean isWebSocketUpgradeRequest(ServletRequest request,
                                                    ServletResponse response) {

        return ((request instanceof HttpServletRequest) &&
                (response instanceof HttpServletResponse) &&
                headerContainsToken((HttpServletRequest) request,
                        HttpHeaderConstants.UPGRADE.toString(),
                        HttpHeaderConstants.WEBSOCKET.toString()) &&
                "GET".equalsIgnoreCase(((HttpServletRequest) request).getMethod()));
    }


    public static void doUpgrade(ServerContainer sc, HttpServletRequest req,
                                 HttpServletResponse resp, ServerEndpointConfig sec,
                                 Map<String,String> pathParams)
            throws ServletException, IOException {

        // Validate the rest of the headers and reject the request if that
        // validation fails
        String key;
        String subProtocol = null;
        if (!headerContainsToken(req, HttpHeaderConstants.CONNECTION.toString(),
                HttpHeaderConstants.UPGRADE.toString())) {
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }
        if (!headerContainsToken(req, HttpHeaderConstants.SEC_WEBSOCKET_VERSION.toString(),
                WS_VERSION)) {
            resp.setStatus(426);
            resp.setHeader(HttpHeaderConstants.SEC_WEBSOCKET_VERSION.toString(),
                    WS_VERSION);
            return;
        }
        key = req.getHeader(HttpHeaderConstants.SEC_WEBSOCKET_KEY.toString());
        if (key == null) {
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }


        // Origin check
        String origin = req.getHeader(HttpHeaderConstants.ORIGIN.toString());
        if (!sec.getConfigurator().checkOrigin(origin)) {
            resp.sendError(HttpServletResponse.SC_FORBIDDEN);
            return;
        }
        // Sub-protocols
        List<String> subProtocols = getTokensFromHeader(req,
                HttpHeaderConstants.SEC_WEBSOCKET_PROTOCOL.toString());
        subProtocol = sec.getConfigurator().getNegotiatedSubprotocol(
                sec.getSubprotocols(), subProtocols);

        // Extensions
        // Should normally only be one header but handle the case of multiple
        // headers
        List<Extension> extensionsRequested = new ArrayList<>();
        Enumeration<String> extHeaders = req.getHeaders(HttpHeaderConstants.SEC_WEBSOCKET_EXTENSIONS.toString());
        while (extHeaders.hasMoreElements()) {
            Util.parseExtensionHeader(extensionsRequested, extHeaders.nextElement());
        }
        // Negotiation phase 1. By default this simply filters out the
        // extensions that the server does not support but applications could
        // use a custom configurator to do more than this.
        List<Extension> installedExtensions = null;
        if (sec.getExtensions().size() == 0) {
            installedExtensions = getExtensions();
        } else {
            installedExtensions = new ArrayList<>();
            installedExtensions.addAll(sec.getExtensions());
            installedExtensions.addAll(getExtensions());
        }
        List<Extension> negotiatedExtensionsPhase1 = sec.getConfigurator().getNegotiatedExtensions(
                installedExtensions, extensionsRequested);

        // Negotiation phase 2. Create the Transformations that will be applied
        // to this connection. Note than an extension may be dropped at this
        // point if the client has requested a configuration that the server is
        // unable to support.
//        List<Transformation> transformations = createTransformations(negotiatedExtensionsPhase1);
//
//        List<Extension> negotiatedExtensionsPhase2;
//        if (transformations.isEmpty()) {
//            negotiatedExtensionsPhase2 = Collections.emptyList();
//        } else {
//            negotiatedExtensionsPhase2 = new ArrayList<>(transformations.size());
//            for (Transformation t : transformations) {
//                negotiatedExtensionsPhase2.add(t.getExtensionResponse());
//            }
//        }

        // Build the transformation pipeline
        StringBuilder responseHeaderExtensions = new StringBuilder();
        boolean first = true;
        for (Extension t : installedExtensions) {
            if (first) {
                first = false;
            } else {
                responseHeaderExtensions.append(',');
            }
            append(responseHeaderExtensions, t);
        }

        // Now we have the full pipeline, validate the use of the RSV bits.
//        if (transformation != null && !transformation.validateRsvBits(0)) {
//            throw new ServletException(sm.getString("upgradeUtil.incompatibleRsv"));
//        }

        // If we got this far, all is good. Accept the connection.
        resp.setHeader(HttpHeaderConstants.UPGRADE.toString(),
                HttpHeaderConstants.WEBSOCKET.toString());
        resp.setHeader(HttpHeaderConstants.CONNECTION.toString(),
                HttpHeaderConstants.UPGRADE.toString());
        resp.setHeader(HandshakeResponse.SEC_WEBSOCKET_ACCEPT,
                getWebSocketAccept(key));
        if (subProtocol != null && subProtocol.length() > 0) {
            // RFC6455 4.2.2 explicitly states "" is not valid here
            resp.setHeader(HttpHeaderConstants.SEC_WEBSOCKET_PROTOCOL.toString(), subProtocol);
        }
        if (responseHeaderExtensions.length() > 0) {
            resp.setHeader(HttpHeaderConstants.SEC_WEBSOCKET_EXTENSIONS.toString(), responseHeaderExtensions.toString());
        }

        WsHandshakeRequest wsRequest = new WsHandshakeRequest(req, pathParams);
        WsHandshakeResponse wsResponse = new WsHandshakeResponse();
        ServerEndpointConfigWrapper perSessionServerEndpointConfig =
                new ServerEndpointConfigWrapper(sec);
        sec.getConfigurator().modifyHandshake(perSessionServerEndpointConfig,
                wsRequest, wsResponse);
        wsRequest.finished();

        // Add any additional headers
        for (Entry<String,List<String>> entry :
                wsResponse.getHeaders().entrySet()) {
            for (String headerValue: entry.getValue()) {
                resp.addHeader(entry.getKey(), headerValue);
            }
        }

        Endpoint ep;
        try {
            Class<?> clazz = sec.getEndpointClass();
            if (Endpoint.class.isAssignableFrom(clazz)) {
                ep = (Endpoint) sec.getConfigurator().getEndpointInstance(
                        clazz);
            } else {
//                ep = new PojoEndpointServer();
//                // Need to make path params available to POJO
//                perSessionServerEndpointConfig.getUserProperties().put(
//                        org.apache.tomcat.websocket.pojo.Constants.POJO_PATH_PARAM_KEY, pathParams);
            }
        } catch (InstantiationException e) {
            throw new ServletException(e);
        }


//        WsHttpUpgradeHandler handler = req.upgrade(WsHttpUpgradeHandler.class);

//        WsHttpUpgradeHandler wsHandler =
//                req.upgrade(WsHttpUpgradeHandler.class);
//        wsHandler.preInit(ep, perSessionServerEndpointConfig, sc, wsRequest,
//                negotiatedExtensionsPhase2, subProtocol, transformation, pathParams,
//                req.isSecure());
    }

    private static List<Extension> getExtensions(){
        return new ArrayList<>();
    }

    private static void append(StringBuilder sb, Extension extension) {
        if (extension == null || extension.getName() == null || extension.getName().length() == 0) {
            return;
        }
        sb.append(extension.getName());
        for (Extension.Parameter p : extension.getParameters()) {
            sb.append(';');
            sb.append(p.getName());
            if (p.getValue() != null) {
                sb.append('=');
                sb.append(p.getValue());
            }
        }
    }


    /*
     * This only works for tokens. Quoted strings need more sophisticated
     * parsing.
     */
    private static boolean headerContainsToken(HttpServletRequest req,
                                               String headerName, String target) {
        Enumeration<String> headers = req.getHeaders(headerName);
        while (headers.hasMoreElements()) {
            String header = headers.nextElement();
            String[] tokens = header.split(",");
            for (String token : tokens) {
                if (target.equalsIgnoreCase(token.trim())) {
                    return true;
                }
            }
        }
        return false;
    }


    /*
     * This only works for tokens. Quoted strings need more sophisticated
     * parsing.
     */
    private static List<String> getTokensFromHeader(HttpServletRequest req,
                                                    String headerName) {
        List<String> result = new ArrayList<>();
        Enumeration<String> headers = req.getHeaders(headerName);
        while (headers.hasMoreElements()) {
            String header = headers.nextElement();
            String[] tokens = header.split(",");
            for (String token : tokens) {
                result.add(token.trim());
            }
        }
        return result;
    }


    private static String getWebSocketAccept(String key) {
        byte[] digest = MessageDigestUtil.digestSHA1(
                key.getBytes(StandardCharsets.ISO_8859_1), WS_ACCEPT);
        return encodeBase64String(digest);
    }

    private static String encodeBase64String(byte[] input) {
        sun.misc.BASE64Encoder encoder = new sun.misc.BASE64Encoder();
        String base64 = encoder.encode(input);
        return base64;
    }

    public static class MessageDigestUtil {

        private static final String MD5 = "MD5";
        private static final String SHA1 = "SHA-1";

        private static final Map<String,Queue<MessageDigest>> queues =
                new HashMap<>();

        private MessageDigestUtil() {
            // Hide default constructor for this utility class
        }

        static {
            try {
                // Init commonly used algorithms
                init(MD5);
                init(SHA1);
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalArgumentException(e);
            }
        }

        public static byte[] digestMD5(byte[]... input) {
            return digest(MD5, input);
        }

        public static byte[] digestSHA1(byte[]... input) {
            return digest(SHA1, input);
        }

        public static byte[] digest(String algorithm, byte[]... input) {
            return digest(algorithm, 1, input);
        }


        public static byte[] digest(String algorithm, int rounds, byte[]... input) {

            Queue<MessageDigest> queue = queues.get(algorithm);
            if (queue == null) {
                throw new IllegalStateException("Must call init() first");
            }

            MessageDigest md = queue.poll();
            if (md == null) {
                try {
                    md = MessageDigest.getInstance(algorithm);
                } catch (NoSuchAlgorithmException e) {
                    // Ignore. Impossible if init() has been successfully called
                    // first.
                    throw new IllegalStateException("Must call init() first");
                }
            }

            // Round 1
            for (byte[] bytes : input) {
                md.update(bytes);
            }
            byte[] result = md.digest();

            // Subsequent rounds
            if (rounds > 1) {
                for (int i = 1; i < rounds; i++) {
                    md.update(result);
                    result = md.digest();
                }
            }

            queue.add(md);

            return result;
        }


        /**
         * Ensures that {@link #digest(String, byte[][])} will support the specified
         * algorithm. This method <b>must</b> be called and return successfully
         * before using {@link #digest(String, byte[][])}.
         *
         * @param algorithm The message digest algorithm to be supported
         *
         * @throws NoSuchAlgorithmException If the algorithm is not supported by the
         *                                  JVM
         */
        public static void init(String algorithm) throws NoSuchAlgorithmException {
            synchronized (queues) {
                if (!queues.containsKey(algorithm)) {
                    MessageDigest md = MessageDigest.getInstance(algorithm);
                    Queue<MessageDigest> queue = new ConcurrentLinkedQueue<>();
                    queue.add(md);
                    queues.put(algorithm, queue);
                }
            }
        }
    }

    public static class WsHandshakeResponse implements HandshakeResponse {

        private final Map<String,List<String>> headers = new CaseInsensitiveKeyMap<>();

        public WsHandshakeResponse() {
        }

        public WsHandshakeResponse(Map<String,List<String>> headers) {
            for (Map.Entry<String,List<String>> entry : headers.entrySet()) {
                if (this.headers.containsKey(entry.getKey())) {
                    this.headers.get(entry.getKey()).addAll(entry.getValue());
                } else {
                    List<String> values = new ArrayList<>(entry.getValue());
                    this.headers.put(entry.getKey(), values);
                }
            }
        }


        @Override
        public Map<String,List<String>> getHeaders() {
            return headers;
        }
    }

    public static class WsHandshakeRequest implements HandshakeRequest {

        private final URI requestUri;
        private final Map<String,List<String>> parameterMap;
        private final String queryString;
        private final Principal userPrincipal;
        private final Map<String,List<String>> headers;
        private final Object httpSession;

        private volatile HttpServletRequest request;


        public WsHandshakeRequest(HttpServletRequest request, Map<String,String> pathParams) {

            this.request = request;

            queryString = request.getQueryString();
            userPrincipal = request.getUserPrincipal();
            httpSession = request.getSession(false);

            // URI
            StringBuilder sb = new StringBuilder(request.getRequestURI());
            if (queryString != null) {
                sb.append("?");
                sb.append(queryString);
            }
            try {
                requestUri = new URI(sb.toString());
            } catch (URISyntaxException e) {
                throw new IllegalArgumentException(e);
            }

            // ParameterMap
            Map<String,String[]> originalParameters = request.getParameterMap();
            Map<String,List<String>> newParameters =
                    new HashMap<>(originalParameters.size());
            for (Map.Entry<String,String[]> entry : originalParameters.entrySet()) {
                newParameters.put(entry.getKey(),
                        Collections.unmodifiableList(
                                Arrays.asList(entry.getValue())));
            }
            for (Map.Entry<String,String> entry : pathParams.entrySet()) {
                newParameters.put(entry.getKey(),
                        Collections.unmodifiableList(
                                Arrays.asList(entry.getValue())));
            }
            parameterMap = Collections.unmodifiableMap(newParameters);

            // Headers
            Map<String,List<String>> newHeaders = new CaseInsensitiveKeyMap<>();

            Enumeration<String> headerNames = request.getHeaderNames();
            while (headerNames.hasMoreElements()) {
                String headerName = headerNames.nextElement();

                newHeaders.put(headerName, Collections.unmodifiableList(
                        Collections.list(request.getHeaders(headerName))));
            }

            headers = Collections.unmodifiableMap(newHeaders);
        }

        @Override
        public URI getRequestURI() {
            return requestUri;
        }

        @Override
        public Map<String,List<String>> getParameterMap() {
            return parameterMap;
        }

        @Override
        public String getQueryString() {
            return queryString;
        }

        @Override
        public Principal getUserPrincipal() {
            return userPrincipal;
        }

        @Override
        public Map<String,List<String>> getHeaders() {
            return headers;
        }

        @Override
        public boolean isUserInRole(String role) {
            if (request == null) {
                throw new IllegalStateException();
            }

            return request.isUserInRole(role);
        }

        @Override
        public Object getHttpSession() {
            return httpSession;
        }

        /**
         * Called when the HandshakeRequest is no longer required. Since an instance
         * of this class retains a reference to the current HttpServletRequest that
         * reference needs to be cleared as the HttpServletRequest may be reused.
         *
         * There is no reason for instances of this class to be accessed once the
         * handshake has been completed.
         */
        void finished() {
            request = null;
        }
    }

    public static class ServerEndpointConfigWrapper implements ServerEndpointConfig{

        private final ServerEndpointConfig perEndpointConfig;
        private final Map<String,Object> perSessionUserProperties =
                new ConcurrentHashMap<>();

        public ServerEndpointConfigWrapper(ServerEndpointConfig perEndpointConfig) {
            this.perEndpointConfig = perEndpointConfig;
            perSessionUserProperties.putAll(perEndpointConfig.getUserProperties());
        }

        @Override
        public List<Class<? extends Encoder>> getEncoders() {
            return perEndpointConfig.getEncoders();
        }

        @Override
        public List<Class<? extends Decoder>> getDecoders() {
            return perEndpointConfig.getDecoders();
        }

        @Override
        public Map<String,Object> getUserProperties() {
            return perSessionUserProperties;
        }

        @Override
        public Class<?> getEndpointClass() {
            return perEndpointConfig.getEndpointClass();
        }

        @Override
        public String getPath() {
            return perEndpointConfig.getPath();
        }

        @Override
        public List<String> getSubprotocols() {
            return perEndpointConfig.getSubprotocols();
        }

        @Override
        public List<Extension> getExtensions() {
            return perEndpointConfig.getExtensions();
        }

        @Override
        public ServerEndpointConfig.Configurator getConfigurator() {
            return perEndpointConfig.getConfigurator();
        }
    }

    public static class Util {

        // OP Codes
        public static final byte OPCODE_CONTINUATION = 0x00;
        public static final byte OPCODE_TEXT = 0x01;
        public static final byte OPCODE_BINARY = 0x02;
        public static final byte OPCODE_CLOSE = 0x08;
        public static final byte OPCODE_PING = 0x09;
        public static final byte OPCODE_PONG = 0x0A;

        private static final Queue<SecureRandom> randoms =
                new ConcurrentLinkedQueue<>();

        private Util() {
            // Hide default constructor
        }

        static boolean isControl(byte opCode) {
            return (opCode & 0x08) != 0;
        }

        static boolean isText(byte opCode) {
            return opCode == OPCODE_TEXT;
        }


        static boolean isContinuation(byte opCode) {
            return opCode == OPCODE_CONTINUATION;
        }


        static CloseReason.CloseCode getCloseCode(int code) {
            if (code > 2999 && code < 5000) {
                return CloseReason.CloseCodes.getCloseCode(code);
            }
            switch (code) {
                case 1000:
                    return CloseReason.CloseCodes.NORMAL_CLOSURE;
                case 1001:
                    return CloseReason.CloseCodes.GOING_AWAY;
                case 1002:
                    return CloseReason.CloseCodes.PROTOCOL_ERROR;
                case 1003:
                    return CloseReason.CloseCodes.CANNOT_ACCEPT;
                case 1004:
                    // Should not be used in a close frame
                    // return CloseCodes.RESERVED;
                    return CloseReason.CloseCodes.PROTOCOL_ERROR;
                case 1005:
                    // Should not be used in a close frame
                    // return CloseCodes.NO_STATUS_CODE;
                    return CloseReason.CloseCodes.PROTOCOL_ERROR;
                case 1006:
                    // Should not be used in a close frame
                    // return CloseCodes.CLOSED_ABNORMALLY;
                    return CloseReason.CloseCodes.PROTOCOL_ERROR;
                case 1007:
                    return CloseReason.CloseCodes.NOT_CONSISTENT;
                case 1008:
                    return CloseReason.CloseCodes.VIOLATED_POLICY;
                case 1009:
                    return CloseReason.CloseCodes.TOO_BIG;
                case 1010:
                    return CloseReason.CloseCodes.NO_EXTENSION;
                case 1011:
                    return CloseReason.CloseCodes.UNEXPECTED_CONDITION;
                case 1012:
                    // Not in RFC6455
                    // return CloseCodes.SERVICE_RESTART;
                    return CloseReason.CloseCodes.PROTOCOL_ERROR;
                case 1013:
                    // Not in RFC6455
                    // return CloseCodes.TRY_AGAIN_LATER;
                    return CloseReason.CloseCodes.PROTOCOL_ERROR;
                case 1015:
                    // Should not be used in a close frame
                    // return CloseCodes.TLS_HANDSHAKE_FAILURE;
                    return CloseReason.CloseCodes.PROTOCOL_ERROR;
                default:
                    return CloseReason.CloseCodes.PROTOCOL_ERROR;
            }
        }


        static byte[] generateMask() {
            // SecureRandom is not thread-safe so need to make sure only one thread
            // uses it at a time. In theory, the pool could grow to the same size
            // as the number of request processing threads. In reality it will be
            // a lot smaller.

            // Get a SecureRandom from the pool
            SecureRandom sr = randoms.poll();

            // If one isn't available, generate a new one
            if (sr == null) {
                try {
                    sr = SecureRandom.getInstance("SHA1PRNG");
                } catch (NoSuchAlgorithmException e) {
                    // Fall back to platform default
                    sr = new SecureRandom();
                }
            }

            // Generate the mask
            byte[] result = new byte[4];
            sr.nextBytes(result);

            // Put the SecureRandom back in the poll
            randoms.add(sr);

            return result;
        }


        static Class<?> getMessageType(MessageHandler listener) {
            return Util.getGenericType(MessageHandler.class,
                    listener.getClass()).getClazz();
        }


        private static Class<?> getDecoderType(Class<? extends Decoder> decoder) {
            return Util.getGenericType(Decoder.class, decoder).getClazz();
        }


        static Class<?> getEncoderType(Class<? extends Encoder> encoder) {
            return Util.getGenericType(Encoder.class, encoder).getClazz();
        }


        private static <T> TypeResult getGenericType(Class<T> type,
                                                     Class<? extends T> clazz) {

            // Look to see if this class implements the interface of interest

            // Get all the interfaces
            Type[] interfaces = clazz.getGenericInterfaces();
            for (Type iface : interfaces) {
                // Only need to check interfaces that use generics
                if (iface instanceof ParameterizedType) {
                    ParameterizedType pi = (ParameterizedType) iface;
                    // Look for the interface of interest
                    if (pi.getRawType() instanceof Class) {
                        if (type.isAssignableFrom((Class<?>) pi.getRawType())) {
                            return getTypeParameter(
                                    clazz, pi.getActualTypeArguments()[0]);
                        }
                    }
                }
            }

            // Interface not found on this class. Look at the superclass.
            @SuppressWarnings("unchecked")
            Class<? extends T> superClazz =
                    (Class<? extends T>) clazz.getSuperclass();
            if (superClazz == null) {
                // Finished looking up the class hierarchy without finding anything
                return null;
            }

            TypeResult superClassTypeResult = getGenericType(type, superClazz);
            int dimension = superClassTypeResult.getDimension();
            if (superClassTypeResult.getIndex() == -1 && dimension == 0) {
                // Superclass implements interface and defines explicit type for
                // the interface of interest
                return superClassTypeResult;
            }

            if (superClassTypeResult.getIndex() > -1) {
                // Superclass implements interface and defines unknown type for
                // the interface of interest
                // Map that unknown type to the generic types defined in this class
                ParameterizedType superClassType =
                        (ParameterizedType) clazz.getGenericSuperclass();
                TypeResult result = getTypeParameter(clazz,
                        superClassType.getActualTypeArguments()[
                                superClassTypeResult.getIndex()]);
                result.incrementDimension(superClassTypeResult.getDimension());
                if (result.getClazz() != null && result.getDimension() > 0) {
                    superClassTypeResult = result;
                } else {
                    return result;
                }
            }

            if (superClassTypeResult.getDimension() > 0) {
                StringBuilder className = new StringBuilder();
                for (int i = 0; i < dimension; i++) {
                    className.append('[');
                }
                className.append('L');
                className.append(superClassTypeResult.getClazz().getCanonicalName());
                className.append(';');

                Class<?> arrayClazz;
                try {
                    arrayClazz = Class.forName(className.toString());
                } catch (ClassNotFoundException e) {
                    throw new IllegalArgumentException(e);
                }

                return new TypeResult(arrayClazz, -1, 0);
            }

            // Error will be logged further up the call stack
            return null;
        }


        /*
         * For a generic parameter, return either the Class used or if the type
         * is unknown, the index for the type in definition of the class
         */
        private static TypeResult getTypeParameter(Class<?> clazz, Type argType) {
            if (argType instanceof Class<?>) {
                return new TypeResult((Class<?>) argType, -1, 0);
            } else if (argType instanceof ParameterizedType) {
                return new TypeResult((Class<?>)((ParameterizedType) argType).getRawType(), -1, 0);
            } else if (argType instanceof GenericArrayType) {
                Type arrayElementType = ((GenericArrayType) argType).getGenericComponentType();
                TypeResult result = getTypeParameter(clazz, arrayElementType);
                result.incrementDimension(1);
                return result;
            } else {
                TypeVariable<?>[] tvs = clazz.getTypeParameters();
                for (int i = 0; i < tvs.length; i++) {
                    if (tvs[i].equals(argType)) {
                        return new TypeResult(null, i, 0);
                    }
                }
                return null;
            }
        }


        public static void parseExtensionHeader(List<Extension> extensions,
                                                String header) {
            // The relevant ABNF for the Sec-WebSocket-Extensions is as follows:
            //      extension-list = 1#extension
            //      extension = extension-token *( ";" extension-param )
            //      extension-token = registered-token
            //      registered-token = token
            //      extension-param = token [ "=" (token | quoted-string) ]
            //             ; When using the quoted-string syntax variant, the value
            //             ; after quoted-string unescaping MUST conform to the
            //             ; 'token' ABNF.
            //
            // The limiting of parameter values to tokens or "quoted tokens" makes
            // the parsing of the header significantly simpler and allows a number
            // of short-cuts to be taken.

            // Step one, split the header into individual extensions using ',' as a
            // separator
            String unparsedExtensions[] = header.split(",");
            for (String unparsedExtension : unparsedExtensions) {
                // Step two, split the extension into the registered name and
                // parameter/value pairs using ';' as a separator
                String unparsedParameters[] = unparsedExtension.split(";");
                WsExtension extension = new WsExtension(unparsedParameters[0].trim());

                for (int i = 1; i < unparsedParameters.length; i++) {
                    int equalsPos = unparsedParameters[i].indexOf('=');
                    String name;
                    String value;
                    if (equalsPos == -1) {
                        name = unparsedParameters[i].trim();
                        value = null;
                    } else {
                        name = unparsedParameters[i].substring(0, equalsPos).trim();
                        value = unparsedParameters[i].substring(equalsPos + 1).trim();
                        int len = value.length();
                        if (len > 1) {
                            if (value.charAt(0) == '\"' && value.charAt(len - 1) == '\"') {
                                value = value.substring(1, value.length() - 1);
                            }
                        }
                    }
                    // Make sure value doesn't contain any of the delimiters since
                    // that would indicate something went wrong
                    if (containsDelims(name) || containsDelims(value)) {
                        throw new IllegalArgumentException("notToken name="+ name+",value="+ value);
                    }
                    if (value != null &&
                            (value.indexOf(',') > -1 || value.indexOf(';') > -1 ||
                                    value.indexOf('\"') > -1 || value.indexOf('=') > -1)) {
                        throw new IllegalArgumentException(value);
                    }
                    extension.addParameter(new WsExtensionParameter(name, value));
                }
                extensions.add(extension);
            }
        }


        private static boolean containsDelims(String input) {
            if (input == null || input.length() == 0) {
                return false;
            }
            for (char c : input.toCharArray()) {
                switch (c) {
                    case ',':
                    case ';':
                    case '\"':
                    case '=':
                        return true;
                    default:
                        // NO_OP
                }

            }
            return false;
        }

        public static class WsExtensionParameter implements Extension.Parameter {

            private final String name;
            private final String value;

            WsExtensionParameter(String name, String value) {
                this.name = name;
                this.value = value;
            }

            @Override
            public String getName() {
                return name;
            }

            @Override
            public String getValue() {
                return value;
            }
        }

        public static class WsExtension implements Extension {

            private final String name;
            private final List<Parameter> parameters = new ArrayList<>();

            WsExtension(String name) {
                this.name = name;
            }

            void addParameter(Parameter parameter) {
                parameters.add(parameter);
            }

            @Override
            public String getName() {
                return name;
            }

            @Override
            public List<Parameter> getParameters() {
                return parameters;
            }
        }

        private static class TypeResult {
            private final Class<?> clazz;
            private final int index;
            private int dimension;

            public TypeResult(Class<?> clazz, int index, int dimension) {
                this.clazz= clazz;
                this.index = index;
                this.dimension = dimension;
            }

            public Class<?> getClazz() {
                return clazz;
            }

            public int getIndex() {
                return index;
            }

            public int getDimension() {
                return dimension;
            }

            public void incrementDimension(int inc) {
                dimension += inc;
            }
        }
    }


}

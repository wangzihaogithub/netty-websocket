package com.github.netty.websocket;

import com.github.netty.core.constants.HttpHeaderConstants;
import io.netty.channel.*;
import io.netty.handler.codec.http.*;
import io.netty.handler.codec.http.websocketx.WebSocketServerHandshaker13;
import io.netty.handler.codec.http.websocketx.extensions.*;
import io.netty.handler.codec.http.websocketx.extensions.compression.DeflateFrameServerExtensionHandshaker;
import io.netty.handler.codec.http.websocketx.extensions.compression.PerMessageDeflateServerExtensionHandshaker;

import java.util.*;

/**
 * websocket13 握手, 附带协议扩展
 * @author 84215
 */
public class WebSocketServerHandshaker13Extension extends WebSocketServerHandshaker13 {

    private static final String EXTENSION_SEPARATOR = ",";
    private static final String PARAMETER_SEPARATOR = ";";
    private static final char PARAMETER_EQUAL = '=';

    private String httpDecoderContextName;
    private Channel channel;

    private List<WebSocketServerExtensionHandshaker> extensionHandshakers =
            Arrays.asList(new PerMessageDeflateServerExtensionHandshaker(),new DeflateFrameServerExtensionHandshaker());

    WebSocketServerHandshaker13Extension(String webSocketURL, String subprotocols, boolean allowExtensions, int maxFramePayloadLength) {
        super(webSocketURL, subprotocols, allowExtensions, maxFramePayloadLength);
    }

    WebSocketServerHandshaker13Extension(String webSocketURL, String subprotocols, boolean allowExtensions, int maxFramePayloadLength, boolean allowMaskMismatch) {
        super(webSocketURL, subprotocols, allowExtensions, maxFramePayloadLength, allowMaskMismatch);
    }

    @Override
    public ChannelFuture handshake(Channel channel, FullHttpRequest req) {
        this.httpDecoderContextName = getHttpDecoderContextName(channel.pipeline());
        this.channel = channel;

        return handshake(channel, req, null, channel.newPromise());
    }

    @Override
    protected FullHttpResponse newHandshakeResponse(FullHttpRequest req, HttpHeaders headers) {
        FullHttpResponse response = super.newHandshakeResponse(req, headers);
        String requestHeaderValue = req.headers().getAsString(HttpHeaderConstants.SEC_WEBSOCKET_EXTENSIONS);
        if(requestHeaderValue == null || requestHeaderValue.isEmpty()){
            return response;
        }

        String responseHeaderValue = response.headers().getAsString(HttpHeaderNames.SEC_WEBSOCKET_EXTENSIONS);
        String newResponseHeaderValue = handshakeExtension(requestHeaderValue,responseHeaderValue);
        response.headers().set(HttpHeaderConstants.SEC_WEBSOCKET_EXTENSIONS, newResponseHeaderValue);
        return response;
    }

    /**
     * 握手websocket协议扩展
     * @param requestHeaderValue
     * @param responseHeaderValue
     * @return
     */
    private String handshakeExtension(String requestHeaderValue,String responseHeaderValue){
        List<WebSocketServerExtension> validExtensions = getWebSocketServerExtension(requestHeaderValue);
        if(validExtensions != null) {
            for (WebSocketServerExtension extension : validExtensions) {
                WebSocketExtensionData extensionData = extension.newReponseData();
                responseHeaderValue = appendExtension(responseHeaderValue, extensionData.name(), extensionData.parameters());

                if(httpDecoderContextName != null && channel != null) {
                    WebSocketExtensionDecoder decoder = extension.newExtensionDecoder();
                    WebSocketExtensionEncoder encoder = extension.newExtensionEncoder();
                    channel.pipeline().addAfter(httpDecoderContextName, decoder.getClass().getName(), decoder);
                    channel.pipeline().addAfter(httpDecoderContextName, encoder.getClass().getName(), encoder);
                }
            }
        }
        return responseHeaderValue;
    }

    private String getHttpDecoderContextName(ChannelPipeline pipeline){
        ChannelHandlerContext ctx = pipeline.context(HttpRequestDecoder.class);
        if (ctx == null) {
            ctx = pipeline.context(HttpServerCodec.class);
        }
        return ctx == null? null : ctx.name();
    }

    /**
     * 获取websocket协议扩展的实现类
     * @param extensionsHeader
     * @return
     */
    private List<WebSocketServerExtension> getWebSocketServerExtension(String extensionsHeader){
        List<WebSocketServerExtension> validExtensions = null;
        if (extensionsHeader != null) {
            List<WebSocketExtensionData> extensions = WebSocketExtensionUtil.extractExtensions(extensionsHeader);
            int rsv = 0;

            for (WebSocketExtensionData extensionData : extensions) {
                Iterator<WebSocketServerExtensionHandshaker> extensionHandshakersIterator =
                        extensionHandshakers.iterator();
                WebSocketServerExtension validExtension = null;

                while (validExtension == null && extensionHandshakersIterator.hasNext()) {
                    WebSocketServerExtensionHandshaker extensionHandshaker = extensionHandshakersIterator.next();
                    validExtension = extensionHandshaker.handshakeExtension(extensionData);
                }

                if (validExtension != null && ((validExtension.rsv() & rsv) == 0)) {
                    if (validExtensions == null) {
                        validExtensions = new ArrayList<>(1);
                    }
                    rsv = rsv | validExtension.rsv();
                    validExtensions.add(validExtension);
                }
            }
        }
        return validExtensions;
    }

    /**
     * 拼接响应头部的扩展字符串
     * @param currentHeaderValue
     * @param extensionName
     * @param extensionParameters
     * @return
     */
    private static String appendExtension(String currentHeaderValue, String extensionName,Map<String, String> extensionParameters) {
        StringBuilder newHeaderValue = new StringBuilder(
                currentHeaderValue != null ? currentHeaderValue.length() : extensionName.length() + 1);
        if (currentHeaderValue != null && !currentHeaderValue.trim().isEmpty()) {
            newHeaderValue.append(currentHeaderValue);
            newHeaderValue.append(EXTENSION_SEPARATOR);
        }
        newHeaderValue.append(extensionName);
        for (Map.Entry<String, String> extensionParameter : extensionParameters.entrySet()) {
            newHeaderValue.append(PARAMETER_SEPARATOR);
            newHeaderValue.append(extensionParameter.getKey());
            if (extensionParameter.getValue() != null) {
                newHeaderValue.append(PARAMETER_EQUAL);
                newHeaderValue.append(extensionParameter.getValue());
            }
        }
        return newHeaderValue.toString();
    }
}

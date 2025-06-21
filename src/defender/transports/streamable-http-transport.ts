/**
 * Streamable HTTP Transport Handler (2025-06-18 spec) with OAuth Passthrough
 * 
 * This implementation provides a transparent proxy for remote MCP servers
 * that forwards client authentication (OAuth tokens, PATs) while maintaining
 * MCP Defender's security verification capabilities.
 * 
 * ## How It Works
 * 
 * 1. Client configures MCP Defender URL: `http://localhost:28173/github/mcp`
 * 2. Client handles OAuth/PAT authentication (e.g., VS Code's built-in GitHub OAuth)
 * 3. MCP Defender forwards all requests with client's Authorization header
 * 4. All tool calls and responses are verified for security
 * 5. Requests are proxied to the actual target server transparently
 * 
 * ## Client Configuration Examples
 * 
 * **GitHub with VS Code OAuth:**
 * ```json
 * {
 *   "mcpServers": {
 *     "github": {
 *       "url": "http://localhost:28173/github/mcp"
 *     }
 *   }
 * }
 * ```
 * 
 * **GitHub with PAT:**
 * ```json
 * {
 *   "mcpServers": {
 *     "github": {
 *       "url": "http://localhost:28173/github/mcp",
 *       "headers": {
 *         "Authorization": "Bearer ghp_your_token_here"
 *       }
 *     }
 *   }
 * }
 * ```
 */

import http from 'node:http';
import https from 'node:https';
import { URL } from 'node:url';
import crypto from 'node:crypto';
import { verifyToolCall, verifyToolResponse } from '../verification-utils.js';
import { DefenderState, sendMessageToParent } from '../common/types.js';
import { DefenderServerEvent } from '../../services/defender/types.js';
import { getCallKey, trackToolCall, cleanupStaleCalls } from '../utils/tool-call-tracker.js';

/**
 * Streamable HTTP session
 */
interface StreamableSession {
    sessionId: string;
    clientSessionId?: string;
    targetUrl: string;
    serverName: string;
    appName: string;
    sseConnections: Map<string, http.ServerResponse>;
    lastActivity: number;
}

/**
 * Global session storage
 */
const sessions = new Map<string, StreamableSession>();

/**
 * Server configuration for remote MCP servers
 */
interface ServerConfig {
    targetUrl: string;
    requiresAuth?: boolean;
}

/**
 * Configuration for remote servers
 * TODO: This should be loaded from settings/configuration file
 */
const serverConfigs: Map<string, ServerConfig> = new Map([
    ['github:mcp', {
        targetUrl: 'https://api.githubcopilot.com/mcp',
        requiresAuth: true
    }],
    // Add more server configurations as needed
]);

/**
 * Generate a cryptographically secure random string
 */
function generateSecureRandom(length: number = 32): string {
    return crypto.randomBytes(length).toString('base64url');
}

/**
 * Main handler for Streamable HTTP transport
 * Handles both GET (SSE streaming) and POST (message sending) requests
 */
export async function handleStreamableHttpTransport(
    req: http.IncomingMessage,
    res: http.ServerResponse,
    state: DefenderState
) {
    const url = new URL(req.url!, `http://${req.headers.host}`);
    const pathname = url.pathname;

    // Parse server and app name from URL path
    const pathParts = pathname.split('/').filter(p => p);
    let serverName: string;
    let appName: string;

    if (pathParts.length >= 2) {
        appName = pathParts[0];
        serverName = pathParts[1];
    } else if (pathParts.length === 1) {
        appName = 'unknown';
        serverName = pathParts[0];
    } else {
        res.statusCode = 404;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: 'Invalid endpoint path' }));
        return;
    }

    console.log(`Streamable HTTP request: ${req.method} ${pathname} (app: ${appName}, server: ${serverName})`);

    // Route to appropriate handler based on HTTP method
    if (req.method === 'GET') {
        await handleStreamableHttpGet(req, res, serverName, appName, state);
    } else if (req.method === 'POST') {
        await handleStreamableHttpPost(req, res, serverName, appName, state);
    } else if (req.method === 'DELETE') {
        await handleStreamableHttpDelete(req, res, serverName, appName, state);
    } else {
        res.statusCode = 405;
        res.setHeader('Allow', 'GET, POST, DELETE');
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: 'Method not allowed' }));
    }
}

/**
 * Handle GET requests for SSE streaming
 */
async function handleStreamableHttpGet(
    req: http.IncomingMessage,
    res: http.ServerResponse,
    serverName: string,
    appName: string,
    state: DefenderState
) {
    const sessionId = req.headers['mcp-session-id'] as string;

    if (!sessionId) {
        res.statusCode = 400;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: 'Mcp-Session-Id header required' }));
        return;
    }

    const session = sessions.get(sessionId);
    if (!session) {
        res.statusCode = 404;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: 'Session not found' }));
        return;
    }

    // Check Accept header for SSE support
    const acceptHeader = req.headers.accept || '';
    if (!acceptHeader.includes('text/event-stream')) {
        res.statusCode = 406;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: 'Client must accept text/event-stream' }));
        return;
    }

    // Set up SSE connection
    res.writeHead(200, {
        'Content-Type': 'text/event-stream',
        'Cache-Control': 'no-cache, no-transform',
        'Connection': 'keep-alive',
        'Access-Control-Allow-Origin': '*'
    });

    // Generate unique connection ID and store connection
    const connectionId = `${sessionId}-${Date.now()}`;
    session.sseConnections.set(connectionId, res);

    // Clean up on disconnect
    req.on('close', () => {
        console.log(`SSE connection ${connectionId} closed`);
        session.sseConnections.delete(connectionId);
    });

    console.log(`SSE connection established for session ${sessionId}`);

    // Forward SSE connection to target server
    await forwardSseConnectionToTarget(session, res, connectionId, state, req);
}

/**
 * Handle POST requests for sending messages
 */
async function handleStreamableHttpPost(
    req: http.IncomingMessage,
    res: http.ServerResponse,
    serverName: string,
    appName: string,
    state: DefenderState
) {
    // Get request body
    let body = '';
    req.on('data', chunk => { body += chunk.toString(); });
    req.on('end', async () => {
        try {
            const message = JSON.parse(body);

            // Handle initialization request specially
            if (message.method === 'initialize') {
                await handleInitializeRequest(req, res, message, serverName, appName);
                return;
            }

            // All other requests require a session
            const sessionId = req.headers['mcp-session-id'] as string;
            if (!sessionId) {
                res.statusCode = 400;
                res.setHeader('Content-Type', 'application/json');
                res.end(JSON.stringify({
                    jsonrpc: '2.0',
                    id: message.id,
                    error: { code: -32000, message: 'Mcp-Session-Id header required' }
                }));
                return;
            }

            const session = sessions.get(sessionId);
            if (!session) {
                res.statusCode = 404;
                res.setHeader('Content-Type', 'application/json');
                res.end(JSON.stringify({
                    jsonrpc: '2.0',
                    id: message.id,
                    error: { code: -32000, message: 'Session not found' }
                }));
                return;
            }

            // Handle different message types
            if (message.method === 'tools/call') {
                await handleToolCallRequest(req, res, message, session, state);
            } else {
                await handleGenericRequest(req, res, message, session, state);
            }
        } catch (error) {
            console.error('Error processing POST request:', error);
            res.statusCode = 400;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({
                error: 'Invalid JSON in request body'
            }));
        }
    });
}

/**
 * Handle DELETE requests for session termination
 */
async function handleStreamableHttpDelete(
    req: http.IncomingMessage,
    res: http.ServerResponse,
    serverName: string,
    appName: string,
    state: DefenderState
) {
    const sessionId = req.headers['mcp-session-id'] as string;

    if (!sessionId) {
        res.statusCode = 400;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: 'Mcp-Session-Id header required' }));
        return;
    }

    const session = sessions.get(sessionId);
    if (!session) {
        res.statusCode = 404;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({ error: 'Session not found' }));
        return;
    }

    // Close all SSE connections for this session
    for (const [connectionId, sseRes] of session.sseConnections) {
        try {
            sseRes.end();
        } catch (error) {
            console.error(`Error closing SSE connection ${connectionId}:`, error);
        }
    }

    // Remove session
    sessions.delete(sessionId);

    console.log(`Session ${sessionId} terminated`);

    res.statusCode = 200;
    res.setHeader('Content-Type', 'application/json');
    res.end(JSON.stringify({ message: 'Session terminated' }));
}

/**
 * Handle initialization request
 */
async function handleInitializeRequest(
    req: http.IncomingMessage,
    res: http.ServerResponse,
    message: any,
    serverName: string,
    appName: string
) {
    console.log(`Initialize request for ${appName}/${serverName}`);

    // Generate session ID
    const sessionId = generateSecureRandom();

    // Determine target URL from configuration
    const targetUrl = getTargetUrlForServer(appName, serverName);
    if (!targetUrl) {
        res.statusCode = 400;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({
            jsonrpc: '2.0',
            id: message.id,
            error: { code: -32000, message: `No target URL configured for ${appName}/${serverName}` }
        }));
        return;
    }

    // Create session
    const session: StreamableSession = {
        sessionId,
        targetUrl,
        serverName,
        appName,
        sseConnections: new Map(),
        lastActivity: Date.now()
    };

    // Try to initialize connection to target server
    const initResult = await initializeTargetConnection(session, message, req.headers);

    if (!initResult.success) {
        res.statusCode = 500;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({
            jsonrpc: '2.0',
            id: message.id,
            error: { code: -32000, message: initResult.error || 'Failed to initialize target connection' }
        }));
        return;
    }

    // Store session and return success response
    sessions.set(sessionId, session);

    res.statusCode = 200;
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Mcp-Session-Id', sessionId);
    res.end(JSON.stringify(initResult.response));
}

/**
 * Initialize connection to target server with passthrough authentication
 */
async function initializeTargetConnection(
    session: StreamableSession,
    initMessage: any,
    clientHeaders: http.IncomingHttpHeaders
): Promise<{
    success: boolean;
    response?: any;
    error?: string
}> {
    try {
        console.log(`Initializing connection to target: ${session.targetUrl}`);

        const serverConfig = getServerConfig(session.appName, session.serverName);

        // Prepare headers for target server
        const headers: Record<string, string> = {
            'Content-Type': 'application/json',
            'Accept': 'application/json, text/event-stream',
            'MCP-Protocol-Version': '2025-06-18'
        };

        // Forward client's authorization header if present
        const authHeader = clientHeaders.authorization;
        if (authHeader) {
            headers['Authorization'] = authHeader;
            console.log('Forwarding client authorization header');
        } else if (serverConfig?.requiresAuth) {
            return {
                success: false,
                error: 'Authorization header required for this server. Please ensure your MCP client is configured with OAuth or PAT authentication.'
            };
        }

        // Send initialize request to target server
        const response = await fetch(session.targetUrl, {
            method: 'POST',
            headers,
            body: JSON.stringify(initMessage)
        });

        if (!response.ok) {
            return { success: false, error: `Target server returned ${response.status}` };
        }

        // Parse successful response
        const data = await response.json();

        // Extract session ID if provided by target server
        const targetSessionId = response.headers.get('mcp-session-id');
        if (targetSessionId) {
            session.clientSessionId = targetSessionId;
        }

        return { success: true, response: data };
    } catch (error) {
        console.error('Error initializing target connection:', error);
        return { success: false, error: `Connection failed: ${error.message}` };
    }
}

/**
 * Handle tool call requests with security verification
 */
async function handleToolCallRequest(
    req: http.IncomingMessage,
    res: http.ServerResponse,
    message: any,
    session: StreamableSession,
    state: DefenderState
) {
    try {
        const toolName = message.params?.name;
        const toolArgs = message.params?.arguments || {};

        if (!toolName) {
            res.statusCode = 400;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({
                jsonrpc: '2.0',
                id: message.id,
                error: { code: -32602, message: 'Missing tool name in tools/call request' }
            }));
            return;
        }

        console.log(`Tool call request: ${toolName}`);

        // Track the tool call for response verification
        const callKey = trackToolCall(
            state,
            toolName,
            message.id,
            session.serverName,
            session.appName,
            toolArgs
        );

        // Verify the tool call
        const serverInfo = {
            serverName: session.serverName,
            serverVersion: '1.0.0',
            appName: session.appName
        };

        const verificationResult = await verifyToolCall(
            toolName,
            toolArgs,
            serverInfo,
            '' // No user intent for HTTP transport
        );

        if (!verificationResult.allowed) {
            console.warn(`Tool call blocked: ${toolName}`);

            // Remove from pending calls
            state.pendingToolCalls.delete(callKey);

            res.statusCode = 200;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({
                jsonrpc: '2.0',
                id: message.id,
                error: {
                    code: -32000,
                    message: 'Tool call blocked: Security policy violation'
                }
            }));
            return;
        }

        // Forward to target server
        await forwardToTargetServer(req, res, message, session);
    } catch (error) {
        console.error('Error handling tool call request:', error);
        res.statusCode = 500;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({
            jsonrpc: '2.0',
            id: message.id,
            error: { code: -32603, message: 'Internal error processing tool call' }
        }));
    }
}

/**
 * Handle generic requests (non-tool calls)
 */
async function handleGenericRequest(
    req: http.IncomingMessage,
    res: http.ServerResponse,
    message: any,
    session: StreamableSession,
    state: DefenderState
) {
    // Forward directly to target server
    await forwardToTargetServer(req, res, message, session);
}

/**
 * Forward SSE connection to target server
 */
async function forwardSseConnectionToTarget(
    session: StreamableSession,
    clientRes: http.ServerResponse,
    connectionId: string,
    state: DefenderState,
    clientReq: http.IncomingMessage
) {
    try {
        // Prepare headers for target server SSE connection
        const headers: Record<string, string> = {
            'Accept': 'text/event-stream',
            'Cache-Control': 'no-cache',
            'MCP-Protocol-Version': '2025-06-18'
        };

        // Forward client's authorization header if present
        const authHeader = clientReq.headers.authorization;
        if (authHeader) {
            headers['Authorization'] = authHeader;
        }

        // Add target server session ID if available
        if (session.clientSessionId) {
            headers['Mcp-Session-Id'] = session.clientSessionId;
        }

        console.log(`Establishing SSE connection to target: ${session.targetUrl}`);

        // Create connection to target server
        const response = await fetch(session.targetUrl, {
            method: 'GET',
            headers
        });

        if (!response.ok) {
            console.error(`Failed to establish SSE connection to target: ${response.status}`);
            clientRes.write(`event: error\ndata: ${JSON.stringify({
                error: `Target server error: ${response.status}`
            })}\n\n`);
            return;
        }

        // Ensure we have an SSE stream
        const contentType = response.headers.get('content-type');
        if (!contentType?.includes('text/event-stream')) {
            console.error('Target server did not return SSE stream');
            clientRes.write(`event: error\ndata: ${JSON.stringify({
                error: 'Target server did not return SSE stream'
            })}\n\n`);
            return;
        }

        // Parse and forward SSE events with response verification
        const reader = response.body?.getReader();
        if (reader) {
            const decoder = new TextDecoder();
            let buffer = '';

            try {
                while (true) {
                    const { done, value } = await reader.read();
                    if (done) break;

                    buffer += decoder.decode(value, { stream: true });

                    // Process complete SSE events
                    const events = buffer.split('\n\n');
                    buffer = events.pop() || ''; // Keep incomplete event in buffer

                    for (const eventData of events) {
                        if (eventData.trim()) {
                            await processSseEvent(eventData, clientRes, session, state);
                        }
                    }
                }
            } finally {
                reader.releaseLock();
            }
        }

        console.log(`SSE connection ${connectionId} to target server closed`);
    } catch (error) {
        console.error(`Error in SSE connection ${connectionId}:`, error);
        clientRes.write(`event: error\ndata: ${JSON.stringify({
            error: 'SSE connection error'
        })}\n\n`);
    }
}

/**
 * Process individual SSE events and verify tool responses
 */
async function processSseEvent(
    eventData: string,
    clientRes: http.ServerResponse,
    session: StreamableSession,
    state: DefenderState
) {
    try {
        // Parse SSE event format (event: type\ndata: json\n)
        const lines = eventData.split('\n');
        let eventType = '';
        let data = '';

        for (const line of lines) {
            if (line.startsWith('event:')) {
                eventType = line.substring(6).trim();
            } else if (line.startsWith('data:')) {
                data += line.substring(5).trim();
            }
        }

        // If no explicit event type, default to 'message'
        if (!eventType && data) {
            eventType = 'message';
        }

        // Try to parse JSON data
        let parsedData = null;
        try {
            parsedData = JSON.parse(data);
        } catch (e) {
            // Not JSON, pass through as-is
        }

        // Verify tool responses if this looks like a tool call response
        let shouldBlock = false;
        if (parsedData && isToolCallResponse(parsedData)) {
            shouldBlock = await verifyToolResponseInSse(parsedData, session, state);
        }

        if (shouldBlock) {
            // Send error event instead of the original response
            clientRes.write(`event: error\ndata: ${JSON.stringify({
                jsonrpc: '2.0',
                id: parsedData.id,
                error: {
                    code: -32000,
                    message: 'Tool response blocked: Security policy violation'
                }
            })}\n\n`);
        } else {
            // Forward the original event
            clientRes.write(eventData + '\n\n');
        }
    } catch (error) {
        console.error('Error processing SSE event:', error);
        // Forward the original event on error
        clientRes.write(eventData + '\n\n');
    }
}

/**
 * Check if a parsed data object looks like a tool call response
 */
function isToolCallResponse(data: any): boolean {
    return data &&
        data.jsonrpc === '2.0' &&
        data.id &&
        (data.result || data.error);
}

/**
 * Verify tool response in SSE stream
 */
async function verifyToolResponseInSse(
    responseData: any,
    session: StreamableSession,
    state: DefenderState
): Promise<boolean> {
    try {
        // Look for pending tool call to get tool name
        const callKey = `${session.sessionId}-${responseData.id}`;
        const pendingCall = state.pendingToolCalls.get(callKey);

        if (!pendingCall) {
            console.warn(`No pending tool call found for response ${responseData.id}`);
            return false; // Don't block if we can't verify
        }

        const serverInfo = {
            serverName: session.serverName,
            serverVersion: 'unknown',
            appName: session.appName
        };

        // Verify the tool response
        const verification = await verifyToolResponse(
            pendingCall.toolName,
            responseData,
            serverInfo
        );

        // Clean up pending call
        state.pendingToolCalls.delete(callKey);

        return !verification.allowed;
    } catch (error) {
        console.error('Error verifying tool response in SSE:', error);
        return false; // Don't block on verification errors
    }
}

/**
 * Verify tool response in JSON format
 */
async function verifyToolResponseInJson(
    responseData: any,
    originalMessage: any,
    session: StreamableSession
): Promise<boolean> {
    try {
        // Extract tool name from original message
        const toolName = originalMessage.params?.name;
        if (!toolName) {
            console.warn('No tool name found in original message');
            return false; // Don't block if we can't verify
        }

        const serverInfo = {
            serverName: session.serverName,
            serverVersion: 'unknown',
            appName: session.appName
        };

        // Verify the tool response
        const verification = await verifyToolResponse(
            toolName,
            responseData,
            serverInfo
        );

        return !verification.allowed;
    } catch (error) {
        console.error('Error verifying tool response in JSON:', error);
        return false; // Don't block on verification errors
    }
}

/**
 * Forward request to target server with passthrough authentication
 */
async function forwardToTargetServer(
    req: http.IncomingMessage,
    res: http.ServerResponse,
    message: any,
    session: StreamableSession
) {
    try {
        // Prepare headers
        const headers: Record<string, string> = {
            'Content-Type': 'application/json',
            'Accept': 'application/json, text/event-stream',
            'MCP-Protocol-Version': '2025-06-18'
        };

        // Forward client's authorization header if present
        const authHeader = req.headers.authorization;
        if (authHeader) {
            headers['Authorization'] = authHeader;
        }

        // Add target server session ID if available
        if (session.clientSessionId) {
            headers['Mcp-Session-Id'] = session.clientSessionId;
        }

        console.log(`Forwarding request to target: ${session.targetUrl}`);

        const response = await fetch(session.targetUrl, {
            method: 'POST',
            headers,
            body: JSON.stringify(message)
        });

        if (!response.ok) {
            console.error(`Target server error: ${response.status}`);
            res.statusCode = 502;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify({
                jsonrpc: '2.0',
                id: message.id,
                error: { code: -32000, message: `Target server error: ${response.status}` }
            }));
            return;
        }

        // Check if response is SSE stream
        const contentType = response.headers.get('content-type');
        if (contentType?.includes('text/event-stream')) {
            // Handle SSE streaming response
            res.writeHead(200, {
                'Content-Type': 'text/event-stream',
                'Cache-Control': 'no-cache, no-transform',
                'Connection': 'keep-alive'
            });

            // Pipe the SSE stream with verification
            const reader = response.body?.getReader();
            if (reader) {
                const decoder = new TextDecoder();
                let buffer = '';

                try {
                    while (true) {
                        const { done, value } = await reader.read();
                        if (done) break;

                        buffer += decoder.decode(value, { stream: true });

                        // Process complete SSE events
                        const events = buffer.split('\n\n');
                        buffer = events.pop() || '';

                        for (const eventData of events) {
                            if (eventData.trim()) {
                                // Parse and verify each event
                                const lines = eventData.split('\n');
                                let data = '';
                                for (const line of lines) {
                                    if (line.startsWith('data:')) {
                                        data += line.substring(5).trim();
                                    }
                                }

                                let shouldBlock = false;
                                if (data) {
                                    try {
                                        const parsedData = JSON.parse(data);
                                        if (isToolCallResponse(parsedData)) {
                                            shouldBlock = await verifyToolResponseInJson(parsedData, message, session);
                                        }
                                    } catch (e) {
                                        // Not JSON, pass through
                                    }
                                }

                                if (shouldBlock) {
                                    res.write(`event: error\ndata: ${JSON.stringify({
                                        jsonrpc: '2.0',
                                        id: message.id,
                                        error: {
                                            code: -32000,
                                            message: 'Tool response blocked: Security policy violation'
                                        }
                                    })}\n\n`);
                                } else {
                                    res.write(eventData + '\n\n');
                                }
                            }
                        }
                    }
                } finally {
                    reader.releaseLock();
                }
            }

            res.end();
        } else {
            // Handle JSON response
            const data = await response.json();

            // Verify tool response if this is a tools/call response
            if (message.method === 'tools/call' && data.result) {
                const shouldBlock = await verifyToolResponseInJson(data, message, session);
                if (shouldBlock) {
                    res.statusCode = 200;
                    res.setHeader('Content-Type', 'application/json');
                    res.end(JSON.stringify({
                        jsonrpc: '2.0',
                        id: message.id,
                        error: {
                            code: -32000,
                            message: 'Tool response blocked: Security policy violation'
                        }
                    }));
                    return;
                }
            }

            res.statusCode = 200;
            res.setHeader('Content-Type', 'application/json');
            res.end(JSON.stringify(data));
        }
    } catch (error) {
        console.error('Error forwarding to target server:', error);
        res.statusCode = 502;
        res.setHeader('Content-Type', 'application/json');
        res.end(JSON.stringify({
            jsonrpc: '2.0',
            id: message.id,
            error: { code: -32000, message: 'Failed to forward request to target server' }
        }));
    }
}

/**
 * Get target URL for a server
 */
function getTargetUrlForServer(appName: string, serverName: string): string | null {
    const key = `${appName}:${serverName}`;
    const config = serverConfigs.get(key);
    return config?.targetUrl || null;
}

/**
 * Get server configuration
 */
function getServerConfig(appName: string, serverName: string): ServerConfig | null {
    const key = `${appName}:${serverName}`;
    return serverConfigs.get(key) || null;
}

/**
 * Cleanup expired sessions
 */
export function cleanupSessions() {
    const now = Date.now();
    const SESSION_TIMEOUT = 24 * 60 * 60 * 1000; // 24 hours

    // Cleanup expired sessions
    for (const [sessionId, session] of sessions) {
        if (now - session.lastActivity > SESSION_TIMEOUT) {
            console.log(`Cleaning up expired session: ${sessionId}`);

            // Close SSE connections
            for (const [connectionId, sseRes] of session.sseConnections) {
                try {
                    sseRes.end();
                } catch (error) {
                    console.error(`Error closing SSE connection ${connectionId}:`, error);
                }
            }

            sessions.delete(sessionId);
        }
    }
}

// Setup periodic cleanup
setInterval(cleanupSessions, 60 * 60 * 1000); // Run every hour 
import type { WebSocketMessage, Threat } from '../types';

type MessageHandler = (message: WebSocketMessage) => void;
type ThreatHandler = (threat: Threat) => void;

class WebSocketService {
  private ws: WebSocket | null = null;
  private reconnectAttempts = 0;
  private reconnectDelay = 1000;
  private maxReconnectDelay = 30000; // cap backoff at 30s
  private shouldReconnect = true;
  private messageHandlers: Set<MessageHandler> = new Set();
  private threatHandlers: Set<ThreatHandler> = new Set();
  private isConnecting = false;

  constructor() {
    this.connect();
  }

  connect() {
    if (this.isConnecting || this.ws?.readyState === WebSocket.OPEN) {
      return;
    }

    this.isConnecting = true;
    this.shouldReconnect = true;
    const wsUrl = import.meta.env.VITE_WS_URL || 'ws://localhost:8000/api/v2/ws';

    try {
      this.ws = new WebSocket(wsUrl);

      this.ws.onopen = () => {
        console.log('WebSocket connected');
        this.isConnecting = false;
        this.reconnectAttempts = 0;
      };

      this.ws.onmessage = (event) => {
        try {
          const message: WebSocketMessage = JSON.parse(event.data);

          // Notify all message handlers
          this.messageHandlers.forEach(handler => handler(message));

          // If it's a threat message, notify threat handlers
          if (message.type === 'threat' && message.data) {
            this.threatHandlers.forEach(handler => handler(message.data));
          }
        } catch (error) {
          console.error('Failed to parse WebSocket message:', error);
        }
      };

      this.ws.onerror = (error) => {
        console.error('WebSocket error:', error);
        this.isConnecting = false;
      };

      this.ws.onclose = () => {
        console.log('WebSocket disconnected');
        this.isConnecting = false;
        this.attemptReconnect();
      };
    } catch (error) {
      console.error('Failed to create WebSocket:', error);
      this.isConnecting = false;
      this.attemptReconnect();
    }
  }

  private attemptReconnect() {
    // Retry indefinitely with exponential backoff capped at
    // maxReconnectDelay. If the backend restarts (or the network blips)
    // while a dashboard is open, the live feed recovers on its own
    // instead of going dead until a manual refresh. reconnectAttempts is
    // reset to 0 on a successful open (see onopen), so the backoff
    // restarts from 1s after each recovery.
    if (!this.shouldReconnect) {
      return;
    }

    const delay = Math.min(
      this.reconnectDelay * Math.pow(2, this.reconnectAttempts),
      this.maxReconnectDelay,
    );
    this.reconnectAttempts++;

    console.log(`WebSocket reconnecting in ${delay}ms (attempt ${this.reconnectAttempts})`);

    setTimeout(() => {
      this.connect();
    }, delay);
  }

  disconnect() {
    this.shouldReconnect = false; // explicit close — don't auto-reconnect
    if (this.ws) {
      this.ws.close();
      this.ws = null;
    }
  }

  send(message: any) {
    if (this.ws?.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(message));
    } else {
      console.warn('WebSocket is not open. Message not sent:', message);
    }
  }

  onMessage(handler: MessageHandler): () => void {
    this.messageHandlers.add(handler);
    return () => this.messageHandlers.delete(handler);
  }

  onThreat(handler: ThreatHandler): () => void {
    this.threatHandlers.add(handler);
    return () => this.threatHandlers.delete(handler);
  }

  isConnected(): boolean {
    return this.ws?.readyState === WebSocket.OPEN;
  }
}

export const websocketService = new WebSocketService();
export default websocketService;

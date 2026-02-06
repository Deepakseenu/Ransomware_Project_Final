let ws = null;
let reconnecting = false;

export function startSocket(onEvent) {
    if (ws && (ws.readyState === WebSocket.OPEN || ws.readyState === WebSocket.CONNECTING)) {
        return;
    }

    const WS_URL = "ws://127.0.0.1:8000/ws/events";
    ws = new WebSocket(WS_URL);

    const wsStatus = document.getElementById("wsStatus");

    ws.onopen = () => {
        reconnecting = false;
        wsStatus.textContent = "ws: connected";
        wsStatus.style.color = "#00ffbf";
        console.log("[WS] connected");
    };

    ws.onclose = () => {
        wsStatus.textContent = "ws: disconnected";
        wsStatus.style.color = "red";
        console.warn("[WS] disconnected");

        if (!reconnecting) {
            reconnecting = true;
            setTimeout(() => startSocket(onEvent), 2000);
        }
    };

    ws.onerror = (e) => {
        wsStatus.textContent = "ws: error";
        wsStatus.style.color = "yellow";
        console.error("[WS] error", e);
    };

    ws.onmessage = (ev) => {
        try {
            const msg = JSON.parse(ev.data);
            if (msg.type === "new_event" && msg.data) {
                onEvent(msg.data);
            } else {
                onEvent(msg);
            }
        } catch (e) {
            console.warn("WS parse error", e);
        }
    };
}

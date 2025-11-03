package services

import (
    "bytes"
    "context"
    "encoding/json"
    "net/http"

    "vpnpannel/internal/config"
)

type PushMessage struct {
    Title string
    Body  string
    Data  map[string]interface{}
}

// SendPushToTokens sends a notification using the FCM legacy HTTP API.
// If FCM_SERVER_KEY is empty, it no-ops.
func SendPushToTokens(ctx context.Context, tokens []string, msg PushMessage) error {
    if config.Current.FCMServerKey == "" || len(tokens) == 0 {
        return nil
    }
    payload := map[string]interface{}{
        "registration_ids": tokens,
        "notification": map[string]interface{}{
            "title": msg.Title,
            "body":  msg.Body,
        },
    }
    if len(msg.Data) > 0 {
        payload["data"] = msg.Data
    }
    body, _ := json.Marshal(payload)
    req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://fcm.googleapis.com/fcm/send", bytes.NewReader(body))
    if err != nil {
        return err
    }
    req.Header.Set("Content-Type", "application/json")
    req.Header.Set("Authorization", "key="+config.Current.FCMServerKey)
    resp, err := http.DefaultClient.Do(req)
    if err != nil {
        return err
    }
    defer resp.Body.Close()
    // We intentionally ignore the response body in this minimal implementation
    return nil
}



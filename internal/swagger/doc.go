package swagger

import "github.com/swaggo/swag"

const docTemplate = `{
  "swagger": "2.0",
  "info": {
    "title": "VPN Panel API",
    "version": "1.0"
  },
  "basePath": "/",
  "schemes": ["http", "https"],
  "consumes": ["application/json"],
  "produces": ["application/json"],
  "paths": {
    "/api/v1/auth/login": {
      "post": {
        "summary": "Login and receive JWT",
        "parameters": [
          {"in": "body", "name": "body", "required": true, "schema": {"$ref": "#/definitions/AuthLoginRequest"}}
        ],
        "responses": {
          "200": {"description": "OK", "schema": {"$ref": "#/definitions/AuthToken"}}
        }
      }
    },
    "/api/v1/auth/no-login": {
      "post": {
        "summary": "Guest login using device_id",
        "parameters": [
          {"in": "body", "name": "body", "required": true, "schema": {"$ref": "#/definitions/NoLoginRequest"}}
        ],
        "responses": {
          "200": {"description": "OK", "schema": {"$ref": "#/definitions/AuthToken"}}
        }
      }
    },
    "/api/v1/profile": {
      "get": {
        "summary": "Get profile (requires Bearer token)",
        "parameters": [
          {"in": "header", "name": "Authorization", "type": "string", "required": true}
        ],
        "responses": {
          "200": {"description": "OK"}
        }
      }
    },
    "/api/v1/nodes": {
      "get": {
        "summary": "Get active nodes",
        "responses": {
          "200": {"description": "OK", "schema": {"type": "object"}}
        }
      }
    },
    "/api/v1/splash/conf": {
      "post": {
        "summary": "Get splash_conf_count nodes: one ads node plus the rest non-ads",
        "description": "Returns splash_conf_count nodes in total (minimum 2): one ads node and splash_conf_count-1 non-ads nodes. When the splash_diverse_servers setting is on, the non-ads picks are spread across distinct server addresses so a client rarely gets several configs from the same server; with fewer distinct addresses than requested it falls back to filling the remainder from the addresses that exist. When the ads_multi_config_enabled setting is on, ads_list carries up to ads_config_count nodes with at most one per distinct server address, so asking for more configs than there are ads servers returns fewer rather than repeating a server; otherwise a single ads node is picked uniformly at random.",
        "parameters": [
          {"in": "body", "name": "body", "required": false, "schema": {"$ref": "#/definitions/SplashConfRequest"}}
        ],
        "responses": {
          "200": {"description": "OK", "schema": {"$ref": "#/definitions/SplashConfResponse"}},
          "503": {"description": "No active ads or non-ads nodes available"}
        }
      }
    },
    "/api/v1/heartbeat": {
      "post": {
        "summary": "Update last seen by token in body",
        "parameters": [
          {"in": "body", "name": "body", "required": true, "schema": {"$ref": "#/definitions/HeartbeatRequest"}}
        ],
        "responses": {
          "200": {"description": "OK"}
        }
      }
    },
    "/api/v1/outages": {
      "post": {
        "summary": "Create outage report (requires Bearer token)",
        "parameters": [
          {"in": "header", "name": "Authorization", "type": "string", "required": true},
          {"in": "body", "name": "body", "required": true, "schema": {"$ref": "#/definitions/OutageRequest"}}
        ],
        "responses": {
          "200": {"description": "OK"}
        }
      }
    },
    "/api/v1/splash": {
      "post": {
        "summary": "Get splash items (live fetch)",
        "responses": {
          "200": {"description": "OK"}
        }
      }
    },
    "/api/v1/last-connection": {
      "post": {
        "summary": "Check in as online using a client-generated token",
        "parameters": [
          {"in": "body", "name": "body", "required": true, "schema": {"$ref": "#/definitions/LastConnectionRequest"}}
        ],
        "responses": {
          "200": {"description": "OK"}
        }
      }
    },
    "/api/v1/invite/code": {
      "post": {
        "summary": "Get (or generate) the caller's own invite code",
        "parameters": [
          {"in": "body", "name": "body", "required": true, "schema": {"$ref": "#/definitions/InviteCodeRequest"}}
        ],
        "responses": {
          "200": {"description": "OK", "schema": {"$ref": "#/definitions/InviteCodeResponse"}}
        }
      }
    },
    "/api/v1/invite/redeem": {
      "post": {
        "summary": "Redeem a friend's invite code (grants both sides an instant reward)",
        "parameters": [
          {"in": "body", "name": "body", "required": true, "schema": {"$ref": "#/definitions/InviteRedeemRequest"}}
        ],
        "responses": {
          "200": {"description": "OK", "schema": {"$ref": "#/definitions/InviteRedeemResponse"}}
        }
      }
    },
    "/api/v1/invite/reward-status": {
      "post": {
        "summary": "Check referral reward eligibility/expiry for the caller",
        "parameters": [
          {"in": "body", "name": "body", "required": true, "schema": {"$ref": "#/definitions/InviteCodeRequest"}}
        ],
        "responses": {
          "200": {"description": "OK", "schema": {"$ref": "#/definitions/InviteRewardStatusResponse"}}
        }
      }
    },
    "/api/v1/settings": {
      "get": {
        "summary": "Get public app settings",
        "responses": {
          "200": {"description": "OK", "schema": {"$ref": "#/definitions/SettingsResponse"}}
        }
      }
    },
    "/api/v1/wheel": {
      "get": {
        "summary": "Get active lucky-wheel segments",
        "responses": {
          "200": {"description": "OK", "schema": {"$ref": "#/definitions/WheelResponse"}}
        }
      }
    },
    "/api/v1/messages": {
      "post": {
        "summary": "Get in-app reminder messages and how long the caller has been away",
        "parameters": [
          {"in": "body", "name": "body", "required": true, "schema": {"$ref": "#/definitions/ClientTokenRequest"}}
        ],
        "responses": {
          "200": {"description": "OK", "schema": {"$ref": "#/definitions/MessagesResponse"}}
        }
      }
    },
    "/api/v1/app/check-update": {
      "post": {
        "summary": "Check app update",
        "parameters": [
          {"in": "body", "name": "body", "required": true, "schema": {"$ref": "#/definitions/CheckUpdateRequest"}}
        ],
        "responses": {
          "200": {"description": "OK", "schema": {"$ref": "#/definitions/CheckUpdateResponse"}}
        }
      }
    }
  },
  "definitions": {
    "AuthLoginRequest": {
      "type": "object",
      "properties": {
        "email": {"type": "string"},
        "password": {"type": "string"},
        "device_id": {"type": "string"},
        "fcm_token": {"type": "string"}
      }
    },
    "NoLoginRequest": {
      "type": "object",
      "properties": {
        "device_id": {"type": "string"},
        "fcm_token": {"type": "string"}
      }
    },
    "AuthToken": {
      "type": "object",
      "properties": {
        "token": {"type": "string"}
      }
    },
    "SplashConfRequest": {
      "type": "object",
      "properties": {
        "client_key": {"type": "string"},
        "device_id": {"type": "string"}
      }
    },
    "SplashConfResponse": {
      "type": "object",
      "properties": {
        "no_ads": {"$ref": "#/definitions/V2RayNode"},
        "ads": {"$ref": "#/definitions/V2RayNode"},
        "no_ads_list": {"type": "array", "items": {"$ref": "#/definitions/V2RayNode"}},
        "ads_list": {"type": "array", "items": {"$ref": "#/definitions/V2RayNode"}}
      }
    },
    "HeartbeatRequest": {
      "type": "object",
      "properties": {
        "token": {"type": "string"},
        "jwt": {"type": "string"}
      }
    },
    "OutageRequest": {
      "type": "object",
      "properties": {
        "node_id": {"type": "integer"},
        "title": {"type": "string"},
        "description": {"type": "string"}
      }
    },
    "LastConnectionRequest": {
      "type": "object",
      "properties": {
        "token": {"type": "string"}
      }
    },
    "InviteCodeRequest": {
      "type": "object",
      "required": ["token"],
      "properties": {
        "token": {"type": "string", "example": "install-abc123", "description": "The client-generated install id. A user row is created on first sight."}
      }
    },
    "ClientTokenRequest": {
      "type": "object",
      "required": ["token"],
      "properties": {
        "token": {"type": "string", "example": "install-abc123", "description": "The client-generated install id."}
      }
    },
    "AppMessage": {
      "type": "object",
      "description": "An admin-authored reminder. The app displays it in-app and/or schedules it as a local notification; nothing is pushed from the server. id is stable across admin edits, so the app can key its own show-count on it.",
      "properties": {
        "id": {"type": "integer", "example": 31},
        "position": {"type": "integer", "example": 0},
        "title": {"type": "string", "example": "دلمون برات تنگ شده"},
        "body": {"type": "string", "example": "یک هفته‌ست سر نزدی! برگرد و جایزه بگیر."},
        "inactive_days": {"type": "integer", "example": 7, "description": "Only show to users away at least this many days; 0 targets everyone."},
        "repeat_every_days": {"type": "integer", "example": 1, "description": "Re-show cadence in days."},
        "max_shows": {"type": "integer", "example": 3, "description": "Stop after this many shows; 0 is unlimited. Counted by the app, not the server."},
        "show_in_app": {"type": "boolean", "example": true},
        "local_notification": {"type": "boolean", "example": true}
      }
    },
    "MessagesResponse": {
      "type": "object",
      "description": "Active reminders plus how long this caller was away. Read-only: it never updates last-seen.",
      "properties": {
        "messages": {"type": "array", "items": {"$ref": "#/definitions/AppMessage"}},
        "days_since_last_seen": {"type": "integer", "example": 9, "description": "Days the caller was away before the current session. 0 for a fresh install."},
        "previous_open_at_unix": {"type": "integer", "format": "int64", "example": 1784895600, "x-nullable": true, "description": "Null when there is no earlier visit to measure from."},
        "due_message_ids": {"type": "array", "items": {"type": "integer"}, "example": [31], "description": "Messages whose inactive_days threshold the caller currently meets."},
        "server_time": {"type": "string", "example": "2026-08-02T15:39:55.249+03:30"},
        "server_time_unix": {"type": "integer", "format": "int64", "example": 1785672595},
        "server_timezone": {"type": "string", "example": "Asia/Tehran"},
        "server_utc_offset_seconds": {"type": "integer", "example": 12600}
      }
    },
    "InviteCodeResponse": {
      "type": "object",
      "description": "The caller's invite code plus their own remaining ad-free window, so the invite screen needs only this one call. Prefer reward_expires_at_unix and remaining_seconds — they carry no timezone ambiguity. remaining_days/hours/minutes are a non-overlapping breakdown meant to be shown together; days_left/hours_left/minutes_left are legacy totals kept for already-published apps.",
      "properties": {
        "referral_enabled": {"type": "boolean", "example": true},
        "invite_code": {"type": "string", "example": "5FQYZA"},
        "invites_count": {"type": "integer", "example": 3},
        "task_text": {"type": "string", "example": "دوستانت را دعوت کن"},
        "share_text": {"type": "string", "example": "با کد 5FQYZA عضو شو"},
        "instant_reward_enabled": {"type": "boolean", "example": true},
        "inviter_reward_minutes": {"type": "integer", "example": 180},
        "invitee_reward_minutes": {"type": "integer", "example": 1440},
        "reward_active": {"type": "boolean", "example": true},
        "reward_expires_at": {"type": "string", "x-nullable": true, "example": "2026-08-02T18:39:55.249+03:30"},
        "reward_expires_at_unix": {"type": "integer", "format": "int64", "x-nullable": true, "example": 1785683395},
        "remaining_seconds": {"type": "integer", "format": "int64", "example": 10799},
        "remaining_days": {"type": "integer", "example": 0},
        "remaining_hours": {"type": "integer", "example": 2},
        "remaining_minutes": {"type": "integer", "example": 59},
        "days_left": {"type": "integer", "example": 1},
        "hours_left": {"type": "integer", "example": 2},
        "minutes_left": {"type": "integer", "example": 179},
        "server_time": {"type": "string", "example": "2026-08-02T15:39:55.249+03:30"},
        "server_time_unix": {"type": "integer", "format": "int64", "example": 1785672595},
        "server_timezone": {"type": "string", "example": "Asia/Tehran"},
        "server_utc_offset_seconds": {"type": "integer", "example": 12600}
      }
    },
    "InviteRedeemRequest": {
      "type": "object",
      "properties": {
        "token": {"type": "string"},
        "invite_code": {"type": "string"}
      }
    },
    "InviteRedeemResponse": {
      "type": "object",
      "description": "reward_granted_* is what this redemption just added; the remaining_* fields are the caller's total window afterwards.",
      "properties": {
        "referral_enabled": {"type": "boolean", "example": true},
        "ok": {"type": "boolean", "example": true},
        "reward_granted_minutes": {"type": "integer", "example": 1440},
        "reward_granted_seconds": {"type": "integer", "example": 86400},
        "reward_active": {"type": "boolean", "example": true},
        "reward_expires_at": {"type": "string", "x-nullable": true, "example": "2026-08-03T15:39:55.249+03:30"},
        "reward_expires_at_unix": {"type": "integer", "format": "int64", "x-nullable": true, "example": 1785758995},
        "remaining_seconds": {"type": "integer", "format": "int64", "example": 86399},
        "remaining_days": {"type": "integer", "example": 0},
        "remaining_hours": {"type": "integer", "example": 23},
        "remaining_minutes": {"type": "integer", "example": 59},
        "days_left": {"type": "integer", "example": 1},
        "hours_left": {"type": "integer", "example": 23},
        "minutes_left": {"type": "integer", "example": 1439},
        "server_time": {"type": "string", "example": "2026-08-02T15:39:55.249+03:30"},
        "server_time_unix": {"type": "integer", "format": "int64", "example": 1785672595},
        "server_timezone": {"type": "string", "example": "Asia/Tehran"},
        "server_utc_offset_seconds": {"type": "integer", "example": 12600}
      }
    },
    "InviteRewardStatusResponse": {
      "type": "object",
      "description": "Pure read — polling this never changes the window. All counters are always present and zeroed when there is no reward; only the two timestamps go null.",
      "properties": {
        "referral_enabled": {"type": "boolean", "example": true},
        "invites_count": {"type": "integer", "example": 3},
        "rewarded_referral_count": {"type": "integer", "example": 2},
        "reward_active": {"type": "boolean", "example": true},
        "reward_expires_at": {"type": "string", "x-nullable": true, "example": "2026-08-02T18:39:55.249+03:30"},
        "reward_expires_at_unix": {"type": "integer", "format": "int64", "x-nullable": true, "example": 1785683395},
        "remaining_seconds": {"type": "integer", "format": "int64", "example": 10799},
        "remaining_days": {"type": "integer", "example": 0},
        "remaining_hours": {"type": "integer", "example": 2},
        "remaining_minutes": {"type": "integer", "example": 59},
        "days_left": {"type": "integer", "example": 1},
        "hours_left": {"type": "integer", "example": 2},
        "minutes_left": {"type": "integer", "example": 179},
        "server_time": {"type": "string", "example": "2026-08-02T15:39:55.249+03:30"},
        "server_time_unix": {"type": "integer", "format": "int64", "example": 1785672595},
        "server_timezone": {"type": "string", "example": "Asia/Tehran"},
        "server_utc_offset_seconds": {"type": "integer", "example": 12600}
      }
    },
    "SettingsResponse": {
      "type": "object",
      "properties": {
        "ads_enabled_in_splash": {"type": "boolean"},
        "show_ads_after_splash": {"type": "boolean"},
        "show_ads_on_main_page": {"type": "boolean"},
        "ads_reward_enabled": {"type": "boolean"},
        "ads_app_open_enabled": {"type": "boolean"},
        "current_version": {"type": "string"},
        "ad_unit_id": {"type": "string"},
        "ads_reward_unit": {"type": "string"},
        "ads_unit_open": {"type": "string"},
        "ads_application_id": {"type": "string"},
        "splash_conf_count": {"type": "integer"},
        "updated_app": {"type": "boolean"},
        "privacy_url": {"type": "string"},
        "connected_timeout": {"type": "integer"},
        "reward_display_percent": {"type": "integer"},
        "link_app": {"type": "string"},
        "release_notes": {"type": "string"},
        "connection_timer": {"type": "integer"},
        "current_version_code": {"type": "integer"},
        "wheel_enabled": {"type": "boolean"},
        "referral_enabled": {"type": "boolean"}
      }
    },
    "CheckUpdateRequest": {
      "type": "object",
      "properties": {
        "package_name": {"type": "string"},
        "package": {"type": "string"},
        "version_code": {"type": "integer"},
        "abi": {"type": "string"}
      }
    },
    "CheckUpdateResponse": {
      "type": "object",
      "properties": {
        "update": {"type": "boolean"},
        "version_code": {"type": "integer"},
        "version_name": {"type": "string"},
        "mandatory": {"type": "boolean"},
        "changelog": {"type": "string"},
        "abi": {"type": "string"},
        "url": {"type": "string"},
        "size": {"type": "integer"},
        "sha256": {"type": "string"}
      }
    },
    "V2RayNode": {
      "type": "object",
      "properties": {
        "id": {"type": "integer"},
        "name": {"type": "string"},
        "address": {"type": "string"},
        "port": {"type": "integer"},
        "protocol": {"type": "string"},
        "tags": {"type": "string"},
        "ads": {"type": "boolean"},
        "country_code": {"type": "string"},
        "country_flag": {"type": "string"},
        "is_active": {"type": "boolean"},
        "capacity": {"type": "integer"},
        "raw_link": {"type": "string"}
      }
    },
    "WheelSegment": {
      "type": "object",
      "properties": {
        "id": {"type": "integer"},
        "position": {"type": "integer"},
        "display_type": {"type": "string", "enum": ["text", "icon"]},
        "label": {"type": "string"},
        "icon": {"type": "string"},
        "reward_type": {"type": "string", "enum": ["time", "premium", "none"]},
        "reward_value": {"type": "integer"},
        "color": {"type": "string"},
        "color_is_random": {"type": "boolean"},
        "weight": {"type": "integer"},
        "percent": {"type": "number"}
      }
    },
    "WheelResponse": {
      "type": "object",
      "properties": {
        "segments": {"type": "array", "items": {"$ref": "#/definitions/WheelSegment"}},
        "total_weight": {"type": "integer"}
      }
    }
  }
}`

func init() {
	swag.Register(swag.Name, &swag.Spec{
		Version:          "1.0",
		Title:            "VPN Panel API",
		Description:      "API documentation",
		SwaggerTemplate:  docTemplate,
		InfoInstanceName: swag.Name,
	})
}

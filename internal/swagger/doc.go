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
        "summary": "Get one ads and one non-ads node (30 min lease)",
        "parameters": [
          {"in": "body", "name": "body", "required": false, "schema": {"$ref": "#/definitions/SplashConfRequest"}}
        ],
        "responses": {
          "200": {"description": "OK", "schema": {"$ref": "#/definitions/SplashConfResponse"}}
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
        "summary": "Redeem a friend's invite code",
        "parameters": [
          {"in": "body", "name": "body", "required": true, "schema": {"$ref": "#/definitions/InviteRedeemRequest"}}
        ],
        "responses": {
          "200": {"description": "OK"}
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
      "properties": {
        "token": {"type": "string"}
      }
    },
    "InviteCodeResponse": {
      "type": "object",
      "properties": {
        "invite_code": {"type": "string"},
        "invites_count": {"type": "integer"},
        "invites_required": {"type": "integer"},
        "task_text": {"type": "string"},
        "share_text": {"type": "string"}
      }
    },
    "InviteRedeemRequest": {
      "type": "object",
      "properties": {
        "token": {"type": "string"},
        "invite_code": {"type": "string"}
      }
    },
    "InviteRewardStatusResponse": {
      "type": "object",
      "properties": {
        "eligible": {"type": "boolean"},
        "invites_count": {"type": "integer"},
        "invites_required": {"type": "integer"},
        "reward_active": {"type": "boolean"},
        "reward_expires_at": {"type": "string"},
        "days_left": {"type": "integer"}
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
        "connected_timeout": {"type": "integer"}
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

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
        "summary": "Update last connected node (requires Bearer token)",
        "parameters": [
          {"in": "header", "name": "Authorization", "type": "string", "required": true},
          {"in": "body", "name": "body", "required": true, "schema": {"$ref": "#/definitions/LastConnectionRequest"}}
        ],
        "responses": {
          "200": {"description": "OK"}
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
        "ads": {"$ref": "#/definitions/V2RayNode"}
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
        "node_id": {"type": "integer"}
      }
    },
    "SettingsResponse": {
      "type": "object",
      "properties": {
        "ads_enabled_in_splash": {"type": "boolean"},
        "show_ads_after_splash": {"type": "boolean"},
        "show_ads_on_main_page": {"type": "boolean"},
        "current_version": {"type": "string"},
        "ad_unit_id": {"type": "string"},
        "ads_application_id": {"type": "string"},
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

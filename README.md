# OpenId Connect (OAuth2) Authentication with SSO

This app is a proof of concept that uses the [OpenId Connect (OAuth2)](https://openid.net/connect/) authentication protocol to authenticate users via an external identity provider [Auth0](https://auth0.com). 

This app is designed to be used in production environments where the user is authenticated via an external identity provider.

Main aim of the app is to add an authentication layer to an existing authentication mechanism. This solution will not disturb the existing token based authentication mechanism.

## Prerequisites

- Auth0 Account
- Node v16.x
- Angular v13.x
- Python ~v3.8
- PostgreSQL v9 or greater

## Usage

The app contains two parts:
- api: the API contains the implementation of the authentication layer.
- users-webapp: the webapp contains the UI that redirects certain users to the providers authentication page.
=== Descope ===
Contributors: gaokevin
Tags: authentication, login, sso, passwordless, passkeys
Requires at least: 6.0
Tested up to: 7.1
Requires PHP: 8.0
Stable tag: 1.2.0
License: MIT
License URI: https://opensource.org/licenses/MIT

Add drag and drop authentication to your site with Descope.

== Description ==

Descope for WordPress lets you add passwordless login, social login, passkeys, MFA, and SAML/OIDC SSO to your WordPress site using Descope Flows.

Shortcodes:

* `[descope_wc flow_id="..."]` - embed a Descope flow (sign-in / sign-up) on a page.
* `[descope_saml_login_form]` / `[descope_oidc_login_form]` - SAML or OIDC SSO login.
* `[descope_onetap_form]` - Google One Tap.
* `[descope_logout_button]` - logout button.
* `[descope_user_profile_widget]` - Descope user profile widget.

Full setup guide: https://docs.descope.com/web-development-platforms/setup-guides/wordpress

This plugin connects to the Descope service (https://www.descope.com/) to authenticate users. See the Descope Terms of Service (https://www.descope.com/legal/terms) and Privacy Policy (https://www.descope.com/legal/privacy).

== Installation ==

1. Install the plugin from the WordPress plugin directory, or upload the plugin zip via Plugins > Add New > Upload Plugin.
2. Activate the plugin from Plugins > Installed Plugins.
3. Open the Descope Settings menu and enter your Descope Project ID (https://app.descope.com/settings/project).
4. Optionally configure SAML/OIDC SSO under the SSO Configuration tab.

== Changelog ==

= 1.2.0 =
* Security: derive the WordPress login identity from the validated Descope session.
* Security: harden SAML ACS response handling.
* Security: bind OIDC state to the browser session.
* Security: fix an authentication bypass in user creation and add missing capability checks.
* Security: update onelogin/php-saml to 4.3.1.
* Relicense the plugin under MIT.

= 1.1 =
* OIDC fallback and protected-page OIDC redirect.

= 1.0 =
* Initial release.

# <a title="WordPress, GPL &lt;http://www.gnu.org/licenses/gpl.html&gt;, via Wikimedia Commons" href="https://wordpress.org/"><img width="64" alt="WordPress blue logo" src="https://upload.wikimedia.org/wikipedia/commons/thumb/9/98/WordPress_blue_logo.svg/64px-WordPress_blue_logo.svg.png"></a> by Descope

## [Descope](https://www.descope.com/) for WordPress

[![License: GPL v2](https://img.shields.io/badge/License-GPL_v2-blue.svg)](https://www.gnu.org/licenses/old-licenses/gpl-2.0.en.html)

## Getting Started

### Requirements

- [Descope Project](https://www.descope.com/sign-up)

### Installation

Installation is very straight-forward.

Zip up this entire repo and then import it into WordPress on your WordPress Dashboard. You can follow the instructions [here](https://www.wpbeginner.com/beginners-guide/step-by-step-guide-to-install-a-wordpress-plugin-for-beginners/).

### Activation

After installation, you must activate the plugin within your WordPress site:

1. Open your WordPress Dashboard.
2. Select **Plugins** from the sidebar, and then **Installed Plugins.**
3. Choose **Activate** underneath the plugin's name.

### Configuring Descope

Once you have installed and activated your plugin, you must go to the new `Descope Settings` menu in the left-hand sidebar and input the following:

1. `Project ID` - this is your Descope Project ID you can get from the settings page [here](https://app.descope.com/settings/project).

If you would like to set up SAML or OIDC SSO, you must also input the fields under the [SSO Configuration Tab](https://docs.descope.com/web-development-platforms/setup-guides/wordpress#samloidc-sso).

Now that you've set everything up in the background, let's integrate the plugin features in your actual website. To add any of these tags, you'll need to use shortcode blocks. If you're unfamiliar with WordPress, you can add a shortcode block by following these steps [here](https://wordpress.com/support/wordpress-editor/blocks/shortcode-block/).

### Add Descope Flows to your WP Pages

First, you're going to want to add the Descope flows tag to one of your pages (this will be where the user signs in). To add the Descope flow page to your website, just add a shortcode block to the main text area of any page, and add the shortcode `[descope_wc flow_id="your-flow-id"]`.

The **flow_id** is the id of the Descope flow that you want to implement in your page. You can edit your flows [here](https://app.descope.com/flows), as well as fetch its ID.

### SAML/OIDC SSO

Add the `[descope_saml_login_form]` or `[descope_oidc_login_form]` shortcode to your main page to add SSO capabilities. Follow the steps [here](https://docs.descope.com/web-development-platforms/setup-guides/wordpress#samloidc-sso).

### Google One Tap

Add the `[descope_onetap_form]` shortcode to your page to add Google One Tap to your WordPress site. Follow the steps [here](https://docs.descope.com/web-development-platforms/setup-guides/wordpress#google-one-tap).

### Logout

Add the `[descope_logout_button]` shortcode to your page to add a logout button to your WordPress site.

### User Profile Widget

Add the `[descope_user_profile_widget]` shortcode to your page to add the Descope user profile widget to your WordPress site.

### Protected Page

Add the `[descope_protected_page]` shortcode to your page to redirect users to a specific page if they are not logged in. You will specify the page path you want to redirect the users to in the shortcode itself, for example: `[descope_protected_page redirect_page_path="/login-page/"]`.

### Documentation

Refer to our [documentation](https://docs.descope.com/web-development-platforms/setup-guides/wordpress) for more information on setting up Descope flows, SAML/OIDC SSO, and Google One Tap in your Wordpress site.

### External Services and Components

This plugin relies on Descope's authentication service and components to provide its core functionality. Here's what you need to know:

#### Descope API
- **Service**: Descope API (api.descope.com)
- **Purpose**: Handles all user syncing operations
- **Data Transmitted**: User data for synchronization

#### Required External Components
The plugin loads these components from Descope's CDN as they are essential parts of the authentication service:
- Descope Web Component
- Descope WebJS SDK
- Descope User Profile Widget

#### Account Requirement
A Descope account is required to use this plugin. You can create one at [https://app.descope.com](https://app.descope.com)

---

If you have any questions about Descope, feel free to [reach out](https://docs.descope.com/support/)!

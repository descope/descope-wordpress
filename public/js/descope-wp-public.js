jQuery(document).ready(function () {
    const projectId = descope_ajax_object.clientId;
    const dynamicFields = descope_ajax_object.dynamicFields;
    const baseUrl = descope_ajax_object.baseUrl;
    // get flow Id from shortcode & default to sign up or in if not present
    const flowId = descope_ajax_object.flowId ? descope_ajax_object.flowId : 'sign-up-or-in';
    const providerId = descope_ajax_object.providerId ? descope_ajax_object.providerId : 'google';

    const sdkConfig = {
        projectId: projectId,
        persistTokens: true,
        autoRefresh: true,
    };

    if (baseUrl) {
        sdkConfig.baseUrl = baseUrl;
    }

    const sdk = Descope(sdkConfig);

    let hasReloaded = false;  // To prevent multiple reloads

    async function sendFormData(sessionToken, userDetails, decodedToken) {
        if (!sessionToken || sdk.isJwtExpired(sessionToken)) {
            console.log("Session token is invalid or expired.");
            return;
        }            

        jQuery.ajax({
            url: descope_ajax_object.ajax_url,
            type: 'POST',
            data: {
                action: 'create_wp_user',
                sessionToken: sessionToken,
                userDetails: JSON.stringify(userDetails),
                decodedToken: JSON.stringify(decodedToken),
                dynamicFields: JSON.stringify(dynamicFields),
                nonce: descope_ajax_object.nonce
            },
            success: function (response) {            
                if (response.success && !hasReloaded) {
                    // Redirect or reload after successful login
                    hasReloaded = true;  // Set the flag
                    location.reload();
                }
            },
            error: function (xhr, status, error) {
                console.error('AJAX Error:', error);
            }
        });
    }

    async function handleUserDetails() {
        const user = await sdk.me();
        const sessionToken = sdk.getSessionToken();
        const decodedToken = jwt_decode(sessionToken);
        sendFormData(sessionToken, user.data, decodedToken);
    }

    async function handleOneTap(providerId) {
        const resp = await sdk.fedcm.oneTap(providerId);
        sdk.refresh();
        handleUserDetails();
    }

    const refreshToken = sdk.getRefreshToken();
    const validRefreshToken = refreshToken && !sdk.isJwtExpired(refreshToken);
    const container = document.getElementById("descope-flow-container");
    const isAnonymousUser = refreshToken ? (jwt_decode(refreshToken)["danu"] === true) : false;

    const onetap_container = document.getElementById("descope-onetap-container");

    if (!validRefreshToken && onetap_container != null) {
        handleOneTap(providerId);
    }

    if ((!validRefreshToken || isAnonymousUser) && container != null) {
        container.innerHTML = `<descope-wc style="outline: none;" project-id=${projectId} flow-id=${flowId} ></descope-wc>`;
        const wcElement = document.getElementsByTagName('descope-wc')[0];

        const onSuccess = (e) => {
            sdk.refresh();
            handleUserDetails();
        }

        const onError = (err) => console.log(err);

        if (wcElement) {
            wcElement.addEventListener('success', onSuccess);
            wcElement.addEventListener('error', onError);
        }
    }

    const userProfileContainer = document.getElementById("descope-user-profile-container");
    if (validRefreshToken && !isAnonymousUser && userProfileContainer != null) {
        userProfileContainer.innerHTML = `<descope-user-profile-widget project-id=${projectId} widget-id="user-profile-widget"/></descope-user-profile-widget>`;
    }

    // Add logout functionality
    jQuery(".logoutButton").click(function (event) {
        logout().then((resp) => {
            // After descope logout process completes, redirect to the wordpress logout url
            window.location = descope_ajax_object.logoutUrl;
        });

        async function logout() {
            const resp = await sdk.logout();
        }
    });
});

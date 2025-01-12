jQuery(document).ready(function () {
    const projectId = descope_ajax_object.clientId;
    // get flow Id from shortcode & default to sign up or in if not present
    const flowId = descope_ajax_object.flowId ? descope_ajax_object.flowId : 'sign-up-or-in';
    const sdk = Descope({
        projectId: projectId,
        persistTokens: true,
        autoRefresh: false,
    });

    let hasReloaded = false;  // To prevent multiple reloads

    async function sendFormData(sessionToken, userDetails) {
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
                nonce: descope_ajax_object.nonce
            },
            success: function (response) {
                if (response.success && !hasReloaded) {
                    // Redirect or reload after successful login
                    hasReloaded = true;  // Set the flag
                    location.reload();
                } else {
                    console.error(response.data.message);
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
        sendFormData(sessionToken, user.data);
    }

    const refreshToken = sdk.getRefreshToken();
    const validRefreshToken = refreshToken && !sdk.isJwtExpired(refreshToken);

    if (!validRefreshToken) {
        const container = document.getElementById("descope-flow-container");
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

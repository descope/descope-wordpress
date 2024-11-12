document.addEventListener("DOMContentLoaded", async () => {
    const sdk = Descope({projectId: oneTapParams.projectId});
    const resp = await sdk.fedcm.oneTap(oneTapParams.providerId);
    const user = resp.data.user;
    document.cookie = "wordpress_descope_email=" + user.email + "; path=/; SameSite=None; Secure";
    setTimeout(() => {
        window.location.reload();
    }, 500);
}); 


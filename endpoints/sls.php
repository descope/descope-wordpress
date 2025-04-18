<?php
/**
 *  SP Single Logout Service Endpoint
 */

// should be able to be accessed directly

session_start();

require_once dirname(__DIR__).'/_toolkit_loader.php';

$auth = new OneLogin_Saml2_Auth();

$auth->processSLO();

$errors = $auth->getErrors();

if (empty($errors)) {
    echo 'Successfully logged out';
} else {
    echo htmlentities(implode(', ', $errors));
}

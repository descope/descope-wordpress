(function ($) {
    'use strict';

    /**
     * All of the code for your admin-facing JavaScript source
     * should reside in this file.
     *
     * Note: It has been assumed you will write jQuery code here, so the
     * $ function reference has been prepared for usage within the scope
     * of this function.
     *
     * This enables you to define handlers, for when the DOM is ready:
     *
     * $(function() {
     *
     * });
     *
     * When the window is loaded:
     *
     * $( window ).load(function() {
     *
     * });
     *
     * ...and/or other possibilities.
     *
     * Ideally, it is not considered best practise to attach more than a
     * single DOM-ready or window-load handler for a particular page.
     * Although scripts in the WordPress core, Plugins and Themes may be
     * practising this, we should strive to set a better example in our own work.
     */

    jQuery(function ($) {
        $(".add-repeater-text-field").click(function () {
            var $lastRow = $(".repeater-text-fields-table tbody tr:last");
            var $newRow = $lastRow.clone();
            $newRow.find('input[type="text"]').val("");
            $newRow.find(".remove-repeater-text-field").click(function () {
                $(this).closest("tr").remove();
            });
            $newRow.insertAfter($lastRow);
        });

        $(document).on("click", ".remove-repeater-text-field", function () {
            $(this).closest("tr").remove();
        });
    });

    jQuery(document).ready(function ($) {
        $('#sync-form').on('submit', function (e) {
            e.preventDefault();

            var syncButton = $('#sync-user');
            var selectedRole = $('#user-role').val();

            // Disable the sync button
            syncButton.prop('disabled', true);
            syncButton.text('Sync in progress');

            // Initialize progress bar
            $('#progress-bar').css('width', '0%').attr('aria-valuenow', 0);
            $('#progress-container').show();

            $.ajax({
                url: my_ajax_object.ajax_url,
                type: 'POST',
                data: {
                    action: 'sync_users_to_descope',
                    user_role: selectedRole,
                    security: my_ajax_object.security
                },
                success: function (response) {
                    if (response.success) {
                        alert(response.data.message);
                    } else {
                        alert(response.data.message);
                    }
                },
                error: function (xhr, status, error) {
                    alert('An error occurred: ' + error);
                },
                xhr: function () {
                    var xhr = new window.XMLHttpRequest();
                    xhr.upload.addEventListener('progress', function (evt) {
                        if (evt.lengthComputable) {
                            var percentComplete = evt.loaded / evt.total * 100;
                            $('#progress-bar').css('width', percentComplete + '%').attr('aria-valuenow', percentComplete);
                            $('#progress-bar').text(percentComplete + '%');
                            // Enable the sync button after 100% progress
                            syncButton.prop('disabled', false);
                            syncButton.text('Sync Users');

                            // location.reload();
                        }
                    }, false);
                    return xhr;
                }
            });
        });
    });

    jQuery(document).ready(function ($) {
        $('#clear-log-button').on('click', function (e) {
            e.preventDefault();

            $.ajax({
                url: my_ajax_object.ajax_url,
                type: 'POST',
                data: {
                    action: 'clear_log_file',
                    security: my_ajax_object.security
                },
                success: function (response) {
                    if (response.success) {
                        $('#log-content').html('<p>' + response.data.message + '</p>');
                    } else {
                        alert(response.data.message);
                    }
                },
                error: function (xhr, status, error) {
                    alert('An error occurred: ' + error);
                }
            });
        });
    });


})(jQuery);

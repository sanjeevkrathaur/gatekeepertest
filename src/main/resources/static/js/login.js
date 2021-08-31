jQuery(document).ready(function () {
    // $('#login-btn').on('click', login())
});

function login() {
    var username = $('#level').val() + '#' + $('#username').val();
    var password = $('#password').val();
    var formData = new FormData();
    var csrfHidden = $('#form-login input[type=hidden]');
    formData.append(csrfHidden.attr('name'), csrfHidden.val());
    $.ajax({
        type: 'POST',
        url: '/login',
        headers: {
            "Authorization": "Basic " + btoa(username + ":" + password)
        },
        data: formData,
        processData: false,
        contentType: false,
        success: function (result, status, jqXHR) {
            var targetUrl=jqXHR.getResponseHeader("targetUrl");
            var xsrfCookie=jqXHR.getResponseHeader("XSRF");
            if (xsrfCookie != null) {
                document.cookie = xsrfCookie.replace('HttpOnly;', '');
            }
            if(jqXHR.status==200 && targetUrl != null)
                window.location=targetUrl;

            console.log(result, status, jqXHR)
            // if(jqXHR.getResponseHeader("errorMessage") != null){
            //     //      var springException = '${sessionScope.SPRING_SECURITY_LAST_EXCEPTION}';
            //     //     alert('Exception = ' +springException);
            //     // $("#validation_sign_in_error").empty();
            //     // $('#validation_sign_in_error').text(jqXHR.getResponseHeader("errorMessage"));
            //     // $("#validation_sign_in_error").show();
            //     // $('#signInBtn').attr('disabled', false);
            // }
        },
        error: function (jqXHR, status, error) {
            var targetUrl=jqXHR.getResponseHeader("errorUrl");
            console.log(jqXHR, status, error, targetUrl)

            if(jqXHR.status==401 && targetUrl != null)
                window.location=targetUrl;
        }
    })
}